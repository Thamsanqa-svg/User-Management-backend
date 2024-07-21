using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FreshFlow.Migrations
{
    public partial class RolesSeeded : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "7cdc2502-3dbc-4a4f-abe3-1b0d6ffafe66", "2", "Staff", "Staff" },
                    { "95b43e59-270f-476a-a5fb-5055a26f0905", "4", "Cashier", "Cashier" },
                    { "9860ef89-d6d7-4c76-9bbd-b055d66b5beb", "1", "Admin", "Admin" },
                    { "9c484438-c7a6-4f41-8764-88c2d3bb36bd", "3", "WarehouseManager", "WarehouseManager" }
                });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "7cdc2502-3dbc-4a4f-abe3-1b0d6ffafe66");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "95b43e59-270f-476a-a5fb-5055a26f0905");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "9860ef89-d6d7-4c76-9bbd-b055d66b5beb");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "9c484438-c7a6-4f41-8764-88c2d3bb36bd");
        }
    }
}
