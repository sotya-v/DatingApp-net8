﻿using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API;

[ApiController]
[Route("api/[controller]")]
public class UserController (DataContext context): ControllerBase
{

    [HttpGet]
    public async Task<ActionResult<IEnumerable<AppUser>>> GetUsers()
    {
        var users = await context.Users.ToListAsync();
        return users;
    }

    [HttpGet("{id:int}")]
    public ActionResult<AppUser> GetUser(int id)
    {
        var user = context.Users.Find(id);

        if (user == null) return NotFound();
        return user;
    }
}
