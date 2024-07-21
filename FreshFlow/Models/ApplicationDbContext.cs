using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace FreshFlow.Models
{
    public class ApplicationDbContext:IdentityDbContext<IdentityUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) 
        { 

        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            SeedRoles(builder);
        }
        private static  void SeedRoles (ModelBuilder builder) 
        {
            builder.Entity<IdentityRole>().HasData
                (
                new IdentityRole() { Name = "Admin", ConcurrencyStamp = "1", NormalizedName = "Admin" },
                new IdentityRole() { Name = "Staff", ConcurrencyStamp = "2", NormalizedName = "Staff" },
                new IdentityRole() { Name = "WarehouseManager", ConcurrencyStamp = "3", NormalizedName = "WarehouseManager" },
                new IdentityRole() { Name = "Cashier", ConcurrencyStamp = "4", NormalizedName = "Cashier" }

                );


        }
    }
}
