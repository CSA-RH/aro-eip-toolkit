# GitHub Actions Workflows

## Nightly Build and Release

The `nightly-build.yml` workflow automatically builds and releases the EIP Toolkit on a schedule.

### Features

- **Scheduled builds**: Runs nightly at 2 AM UTC
- **Manual triggers**: Can be manually triggered from the GitHub Actions UI
- **Tag-based releases**: Automatically creates releases when version tags (v*) are pushed
- **Multi-platform**: Builds for all supported platforms:
  - Linux (amd64, arm64)
  - macOS (amd64, arm64)
  - Windows (amd64, arm64)

### How It Works

1. **Nightly Builds**: 
   - Runs automatically every night at 2 AM UTC
   - Creates a pre-release with date-based versioning (e.g., `nightly-20241106`)
   - Uploads binaries for all platforms

2. **Manual Triggers**:
   - Go to Actions → Nightly Build and Release → Run workflow
   - Creates a timestamped pre-release

3. **Tag-based Releases**:
   - Push a tag starting with `v` (e.g., `v0.3.0`)
   - Creates a full release (not pre-release) with changelog

### Customization

To change the schedule, edit the cron expression in `.github/workflows/nightly-build.yml`:
```yaml
schedule:
  - cron: '0 2 * * *'  # 2 AM UTC daily
```

Cron format: `minute hour day-of-month month day-of-week`

Examples:
- `'0 2 * * *'` - 2 AM UTC daily
- `'0 0 * * 0'` - Midnight UTC every Sunday
- `'0 14 * * 1-5'` - 2 PM UTC weekdays

### Permissions

The workflow requires write access to repository contents. This is automatically granted for:
- Workflows in the default branch
- Workflows triggered by repository owners

For other cases, ensure the GitHub Actions token has the `contents: write` permission.

