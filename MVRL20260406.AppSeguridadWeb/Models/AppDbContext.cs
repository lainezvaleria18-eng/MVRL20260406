using Microsoft.EntityFrameworkCore;

namespace MVRL20260406.AppSeguridadWeb.Models
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
        public DbSet<Usuario> Usuarios { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            string passwordHash = "$2a$11$hDEUK3aSHfrxt4SDvkV94.BHbSk2dfR8AX0/.puPHXqVDWcPAwyc6";  // Admin123
            modelBuilder.Entity<Usuario>().HasData(
                new Usuario
                {
                    Id = 1,
                    Login = "admin",
                    PasswordHash = passwordHash,
                    Rol = "Administrador",
                    EstaActivo = true
                }
            );
        }
    }
}


