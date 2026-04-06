using MVRL20260406.AppSeguridadWeb.Models; // Ajustado a tu proyecto
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;

namespace MVRL20260406.AppSeguridadWeb.Controllers // Ajustado a tu proyecto
{
    [Authorize]
    public class UsuariosController : Controller
    {
        private readonly AppDbContext _context;

        public UsuariosController(AppDbContext context)
        {
            _context = context;
        }

        public async Task<IActionResult> Index()
        {
            return View(await _context.Usuarios.ToListAsync());
        }

        public async Task<IActionResult> Details(int? id)
        {
            if (id == null) return NotFound();
            var usuario = await _context.Usuarios.FirstOrDefaultAsync(m => m.Id == id);
            if (usuario == null) return NotFound();
            return View(usuario);
        }

        [Authorize(Roles = "Administrador,Usuario")]
        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Administrador,Usuario")]
        public async Task<IActionResult> Create([Bind("Login,PasswordHash,ConfirmarPassword,Rol,EstaActivo")] Usuario usuario)
        {
            if (ModelState.IsValid)
            {
                // Encripta la contraseña antes de guardar
                usuario.PasswordHash = BCrypt.Net.BCrypt.HashPassword(usuario.PasswordHash);
                _context.Add(usuario);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(usuario);
        }

        [Authorize(Roles = "Administrador,Editor")]
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null) return NotFound();
            var usuario = await _context.Usuarios.FindAsync(id);
            if (usuario == null) return NotFound();
            return View(usuario);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Administrador,Editor")]
        public async Task<IActionResult> Edit(int id, [Bind("Id,Login,Rol,EstaActivo")] Usuario usuario)
        {
            if (id != usuario.Id) return NotFound();
            try
            {
                var usuarioData = await _context.Usuarios.AsNoTracking().FirstOrDefaultAsync(u => u.Id == id);
                if (usuarioData == null) return NotFound();

                usuarioData.Login = usuario.Login;
                usuarioData.Rol = usuario.Rol;
                usuarioData.EstaActivo = usuario.EstaActivo;

                _context.Update(usuarioData);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, $"Ocurrió un error : {ex.Message}");
                return View(usuario);
            }

            return RedirectToAction(nameof(Index));

        }


        [Authorize(Roles = "Administrador")]
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null) return NotFound();
            var usuario = await _context.Usuarios.FirstOrDefaultAsync(m => m.Id == id);
            if (usuario == null) return NotFound();
            return View(usuario);
        }

        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Administrador")]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var usuario = await _context.Usuarios.FindAsync(id);
            if (usuario != null) _context.Usuarios.Remove(usuario);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        [AllowAnonymous]
        public IActionResult Login(string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View(new Usuario());
        }

        [AllowAnonymous]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login([Bind("Login,PasswordHash")] Usuario usuario, string? returnUrl = null)
        {
            try
            {
                ViewData["ReturnUrl"] = returnUrl;
                if (usuario == null || string.IsNullOrEmpty(usuario.Login) || string.IsNullOrEmpty(usuario.PasswordHash))
                {
                    ModelState.AddModelError(string.Empty, "El login y la contraseña son requeridos.");
                    return View(usuario);
                }

                var usuarioDB = await _context.Usuarios.FirstOrDefaultAsync(u => u.Login == usuario.Login && u.EstaActivo == true);

                if (usuarioDB == null || !BCrypt.Net.BCrypt.Verify(usuario.PasswordHash, usuarioDB.PasswordHash))
                {
                    ModelState.AddModelError(string.Empty, "Nombre de usuario o contraseña incorrectos.");
                    return View(usuario);
                }

                var claims = new List<Claim>{
                    new Claim(ClaimTypes.Name, usuarioDB.Login),
                    new Claim(ClaimTypes.Role, usuarioDB.Rol),
                    new Claim("Id", usuarioDB.Id.ToString())
                };

                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));

                if (!string.IsNullOrWhiteSpace(returnUrl)) return Redirect(returnUrl);
                return RedirectToAction("Index", "Home");
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, $"Error: {ex.Message}");
                return View(usuario);
            }
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Login", "Usuarios");
        }

        [AllowAnonymous]
        public IActionResult AccessDenied() => View();
    }
}