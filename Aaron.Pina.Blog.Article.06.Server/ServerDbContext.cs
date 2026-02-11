using Microsoft.EntityFrameworkCore;

namespace Aaron.Pina.Blog.Article._06.Server;

public class ServerDbContext(DbContextOptions<ServerDbContext> options) : DbContext(options)
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<TokenEntity>()
                    .Property(t => t.RefreshToken)
                    .HasMaxLength(512);
        modelBuilder.Entity<UserEntity>()
                    .Property(t => t.Role)
                    .HasMaxLength(512);
    }
    
    public DbSet<TokenEntity> Tokens => Set<TokenEntity>();
    public DbSet<UserEntity>  Users =>  Set<UserEntity>();
}
