using System;
using System.Collections.Generic;

namespace TestResComp3.Models;

public partial class User
{ 
    public int UserId { get; set; }

    public string? UserName { get; set; }

    public string? FullName { get; set; }

    public string? Email { get; set; }

    public string? PasswordHash { get; set; }

    public string? Mobile { get; set; }

    public bool? IsActive { get; set; }

    public virtual ICollection<Role> Roles { get; } = new List<Role>();
}
