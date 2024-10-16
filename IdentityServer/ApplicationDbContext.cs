using Microsoft.EntityFrameworkCore;

namespace IdentityServer;

class ApplicationDbContext(DbContextOptions options) : DbContext(options)
{
    public DbSet<AuthTicket> Tickets { get; set; }
}