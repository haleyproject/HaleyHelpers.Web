using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;

namespace HaleyHelpersWeb.Tests;

internal sealed class TestHostEnvironment(string contentRootPath) : IHostEnvironment
{
    public string EnvironmentName { get; set; } = Environments.Development;
    public string ApplicationName { get; set; } = "HaleyHelpersWeb.Tests";
    public string ContentRootPath { get; set; } = contentRootPath;
    public IFileProvider ContentRootFileProvider { get; set; } =
        new PhysicalFileProvider(contentRootPath);
}
