using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

[Table("Usuarios")]
public class Usuario
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int Id { get; set; }

    [Required(ErrorMessage = "El nombre de usuario es obligatorio")]
    [StringLength(50)]
    public string Login { get; set; }

    [Required(ErrorMessage = "La contraseña es obligatoria")]
    [StringLength(100)]
    [DataType(DataType.Password)]
    [Display(Name = "Contraseña")]
    public string PasswordHash { get; set; }

    [NotMapped]
    [Required(ErrorMessage = "Debe confirmar la contraseña")]
    [Compare("PasswordHash", ErrorMessage = "Las contraseñas no coinciden")]
    [StringLength(100)]
    [DataType(DataType.Password)]
    [Display(Name = "Confirmar Contraseña")]
    public string ConfirmarPassword { get; set; }

    [Required]
    [StringLength(20)]
    [AllowedValues("Administrador", "Editor", "Usuario", ErrorMessage = "Seleccione un rol válido")]
    public string Rol { get; set; }

    public bool EstaActivo { get; set; } = true;
}





