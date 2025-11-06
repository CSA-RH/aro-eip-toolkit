# GitHub Actions Setup Guide

This guide explains how to set up automated nightly builds and releases using GitHub Actions.

## Quick Start

The workflow is already configured in `.github/workflows/nightly-build.yml`. Once you push this to your repository, it will automatically:

1. **Run nightly** at 2 AM UTC
2. **Build for all platforms** (Linux, macOS, Windows - both amd64 and arm64)
3. **Create pre-releases** with date-based versioning (e.g., `nightly-20241106`)

## Setup Steps

### 1. Push the Workflow File

The workflow file is already created. Just commit and push:

```bash
git add .github/workflows/nightly-build.yml
git commit -m "Add GitHub Actions workflow for nightly builds"
git push
```

### 2. Enable GitHub Actions (if not already enabled)

1. Go to your repository on GitHub
2. Click on **Settings** → **Actions** → **General**
3. Ensure "Allow all actions and reusable workflows" is selected
4. Save changes

### 3. Verify Permissions

The workflow needs write access to create releases. This is automatically granted for:
- Workflows in the default branch
- Repository owners

If you encounter permission issues:
1. Go to **Settings** → **Actions** → **General**
2. Under "Workflow permissions", select "Read and write permissions"
3. Check "Allow GitHub Actions to create and approve pull requests" (if needed)

### 4. Test the Workflow

You can manually trigger the workflow to test it:

1. Go to **Actions** tab in your repository
2. Select "Nightly Build and Release" workflow
3. Click "Run workflow"
4. Select the branch (usually `main` or `dev`)
5. Click "Run workflow"

The workflow will build all binaries and create a release.

## How It Works

### Nightly Builds

- **Schedule**: Runs daily at 2 AM UTC
- **Versioning**: Uses date format `nightly-YYYYMMDD` (e.g., `nightly-20241106`)
- **Release Type**: Pre-release (marked as "Pre-release" on GitHub)
- **Binaries**: All 6 platform binaries are included

### Manual Triggers

- **When**: Triggered manually from Actions UI
- **Versioning**: Uses timestamp format `nightly-YYYYMMDD-HHMMSS`
- **Release Type**: Pre-release

### Tag-Based Releases

- **When**: Push a tag starting with `v` (e.g., `v0.3.0`)
- **Versioning**: Uses the tag name
- **Release Type**: Full release (not pre-release)
- **Changelog**: Automatically generated from git commits since last tag

Example:
```bash
git tag v0.3.0
git push origin v0.3.0
```

## Customizing the Schedule

Edit `.github/workflows/nightly-build.yml` and change the cron expression:

```yaml
schedule:
  - cron: '0 2 * * *'  # Current: 2 AM UTC daily
```

Cron format: `minute hour day-of-month month day-of-week`

Examples:
- `'0 0 * * *'` - Midnight UTC daily
- `'0 2 * * 1-5'` - 2 AM UTC weekdays only
- `'0 0 * * 0'` - Midnight UTC every Sunday
- `'0 */6 * * *'` - Every 6 hours

## Viewing Builds

1. Go to **Actions** tab in your repository
2. Click on "Nightly Build and Release"
3. Click on any run to see:
   - Build status for each platform
   - Build logs
   - Artifacts (binaries)
   - Release information

## Downloading Binaries

After a build completes:

1. Go to **Releases** in your repository
2. Find the release (nightly builds are marked as "Pre-release")
3. Download the binary for your platform

Or use the direct download links:
- `https://github.com/CSA-RH/aro-eip-toolkit/releases/download/nightly-YYYYMMDD/eip-toolkit-<platform>`

## Troubleshooting

### Workflow Not Running

1. Check that GitHub Actions is enabled in repository settings
2. Verify the workflow file is in `.github/workflows/` directory
3. Check that the workflow file is in the default branch
4. Look for errors in the Actions tab

### Build Failures

1. Check the build logs in the Actions tab
2. Verify Go version compatibility (currently set to 1.24)
3. Check for dependency issues

### Release Not Created

1. Verify permissions (see step 3 above)
2. Check if a release with the same tag already exists
3. Review the release job logs in Actions

### Missing Binaries

1. Check that all build jobs completed successfully
2. Verify artifact uploads in the build job logs
3. Check artifact retention settings (default: 7 days)

## Advanced Configuration

### Changing Go Version

Edit the workflow file:
```yaml
- name: Set up Go
  uses: actions/setup-go@v5
  with:
    go-version: '1.24'  # Change this
```

### Adding More Platforms

Add entries to the matrix in the build job:
```yaml
- os: ubuntu-latest
  arch: arm64
  goos: linux
  goarch: arm64
  binary_name: eip-toolkit-linux-arm64
```

### Custom Release Notes

Modify the `body` section in the "Create Release" step to customize the release notes format.

## Security Notes

- The workflow uses `GITHUB_TOKEN` which is automatically provided by GitHub Actions
- No additional secrets are required for basic functionality
- The token has permissions scoped to the repository only
- For public repositories, releases are public by default

## Cost Considerations

- GitHub Actions provides 2,000 free minutes/month for private repos
- Public repositories have unlimited free minutes
- Each build uses approximately 10-15 minutes total across all platforms
- Nightly builds = ~30 builds/month = ~300-450 minutes/month (well within free tier)

