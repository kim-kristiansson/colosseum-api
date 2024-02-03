using ColosseumAPI.Models;
using ColosseumAPI.Repositories.Interfaces;
using ColosseumAPI.Services;
using ColosseumAPI.Services.Interfaces;
using Google.Apis.Auth;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;

public class ApplicationUserTests
{
    [Fact]
    public async Task AuthenticateOrRegisterUser_UserExists_ReturnsExistingUser()
    {
        // Arrange
        var mockRepo = new Mock<IApplicationUserRepository>();
        var mockLogger = new Mock<ILogger<ApplicationUserService>>();
        var mockConfiguration = MockConfiguration();
        var mockGoogleTokenValidator = new Mock<IGoogleTokenValidator>();
        var testEmail = "test@example.com";
        var expectedUser = new ApplicationUser { Email = testEmail };

        mockRepo.Setup(x => x.GetByEmailAsync(testEmail)).ReturnsAsync(expectedUser);

        var service = new ApplicationUserService(mockRepo.Object, mockLogger.Object, mockConfiguration.Object, mockGoogleTokenValidator.Object);

        // Act
        var result = await service.AuthenticateOrRegisterUser(new GoogleJsonWebSignature.Payload { Email = testEmail });

        // Assert
        Assert.Equal(expectedUser.Email, result.Email);
    }

    [Fact]
    public void GenerateJwtToken_ValidUser_ReturnsToken()
    {
        // Arrange
        var user = new ApplicationUser { Id = "1", Email = "user@example.com" };
        var mockRepo = new Mock<IApplicationUserRepository>();
        var mockLogger = new Mock<ILogger<ApplicationUserService>>();
        var mockConfiguration = MockConfiguration();
        var mockGoogleTokenValidator = new Mock<IGoogleTokenValidator>();

        var service = new ApplicationUserService(mockRepo.Object, mockLogger.Object, mockConfiguration.Object, mockGoogleTokenValidator.Object);

        // Act
        var token = service.GenerateJwtToken(user);

        // Assert
        Assert.False(string.IsNullOrWhiteSpace(token));
    }

    private Mock<IConfiguration> MockConfiguration()
    {
        var mockConfiguration = new Mock<IConfiguration>();

        var strongKey = "15T5FMep1pzsUDgfz7bb+C0zjYAee3QmHvA4QL9DNJQ=";

        mockConfiguration.Setup(c => c["JwtSettings:Issuer"]).Returns("TestIssuer");
        mockConfiguration.Setup(c => c["JwtSettings:Audience"]).Returns("TestAudience");
        mockConfiguration.Setup(c => c["JwtSettings:SecretKey"]).Returns(strongKey);
        mockConfiguration.Setup(c => c["GoogleAuthSettings:ClientId"]).Returns("TestGoogleClientId");

        return mockConfiguration;
    }
}
