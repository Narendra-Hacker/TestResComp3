using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace TestResComp3.Models;

public partial class Role
{
    public int RoleId { get; set; }

    public string? RoleName { get; set; }

    public int? UserId { get; set; }

    [JsonIgnore]
    public virtual User? User { get; set; }
}
