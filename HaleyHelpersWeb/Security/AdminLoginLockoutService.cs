using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Haley.Models;

public sealed class AdminLoginLockoutService(
    IOptionsMonitor<AdminLoginLockoutOptions> options,
    IHostEnvironment environment,
    TimeProvider timeProvider)
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly SemaphoreSlim _gate = new(1, 1);

    public async ValueTask<AdminLoginLockoutStatus> GetStatusAsync(
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await LoadCurrentAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask<AdminLoginLockoutStatus> RecordFailureAsync(
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var current = await LoadCurrentAsync(cancellationToken).ConfigureAwait(false);
            if (current.IsLocked) return current;

            var maximumAttempts = MaximumAttempts;
            var failedAttempts = current.FailedAttempts + 1;
            var lockedUntil = failedAttempts >= maximumAttempts
                ? timeProvider.GetUtcNow().AddMinutes(LockoutMinutes)
                : null as DateTimeOffset?;
            var state = new AdminLoginLockoutState
            {
                FailedAttempts = failedAttempts,
                LockedUntil = lockedUntil
            };
            await SaveAsync(state, cancellationToken).ConfigureAwait(false);
            return ToStatus(state, maximumAttempts);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask ResetAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            DeleteStateFile();
        }
        finally
        {
            _gate.Release();
        }
    }

    private int MaximumAttempts => Math.Clamp(options.CurrentValue.MaxFailedLoginAttempts, 1, 100);
    private int LockoutMinutes => Math.Clamp(options.CurrentValue.LoginLockoutMinutes, 1, 1_440);
    private string StatePath => Utils.AdminLoginLockoutFile.ResolvePath(
        options.CurrentValue.LoginLockoutStatePath,
        environment.ContentRootPath);

    private async ValueTask<AdminLoginLockoutStatus> LoadCurrentAsync(
        CancellationToken cancellationToken)
    {
        var maximumAttempts = MaximumAttempts;
        var path = StatePath;
        if (!File.Exists(path)) return new(false, 0, maximumAttempts, null);

        AdminLoginLockoutState? state;
        try
        {
            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 4_096,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            state = await JsonSerializer.DeserializeAsync<AdminLoginLockoutState>(
                    stream,
                    SerializerOptions,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException(
                $"Admin login lockout state '{path}' is invalid. Run the reset-lockout terminal command.",
                exception);
        }

        if (state is null)
        {
            throw new InvalidOperationException(
                $"Admin login lockout state '{path}' is empty. Run the reset-lockout terminal command.");
        }

        if (state.LockedUntil.HasValue && state.LockedUntil.Value <= timeProvider.GetUtcNow())
        {
            DeleteStateFile();
            return new(false, 0, maximumAttempts, null);
        }

        state.FailedAttempts = Math.Max(0, state.FailedAttempts);
        return ToStatus(state, maximumAttempts);
    }

    private async ValueTask SaveAsync(
        AdminLoginLockoutState state,
        CancellationToken cancellationToken)
    {
        var path = StatePath;
        var directory = Path.GetDirectoryName(path)
            ?? throw new InvalidOperationException(
                $"Unable to resolve the directory for lockout state '{path}'.");
        Directory.CreateDirectory(directory);

        var temporaryPath = $"{path}.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp";
        try
        {
            await using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 4_096,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(
                        stream,
                        state,
                        SerializerOptions,
                        cancellationToken)
                    .ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            File.Move(temporaryPath, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    private void DeleteStateFile()
    {
        var path = StatePath;
        if (File.Exists(path)) File.Delete(path);
    }

    private AdminLoginLockoutStatus ToStatus(
        AdminLoginLockoutState state,
        int maximumAttempts)
    {
        var isLocked = state.LockedUntil.HasValue &&
                       state.LockedUntil.Value > timeProvider.GetUtcNow();
        return new(
            isLocked,
            state.FailedAttempts,
            maximumAttempts,
            isLocked ? state.LockedUntil : null);
    }
}
