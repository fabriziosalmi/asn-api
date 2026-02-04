# GitHub Pages & Release Setup Instructions

This document provides instructions for completing the GitHub Pages setup and creating the v1.0.0 release.

## GitHub Pages Setup

### Step 1: Enable GitHub Pages

1. Go to the repository on GitHub: https://github.com/fabriziosalmi/asn-api
2. Navigate to **Settings** → **Pages**
3. Under **Source**, select **"GitHub Actions"**
4. Click **Save**

### Step 2: Trigger the Deployment

The workflow is configured to run automatically when code is merged to the `main` branch. You can also trigger it manually:

1. Go to the **Actions** tab in the repository
2. Select **"Deploy VitePress Docs to GitHub Pages"** from the workflows list
3. Click **"Run workflow"** button
4. Select the `main` branch
5. Click **"Run workflow"** to start the deployment

### Step 3: Verify Deployment

Once the workflow completes successfully (usually takes 2-3 minutes):

1. The documentation will be accessible at: **https://fabriziosalmi.github.io/asn-api/**
2. Check the workflow run logs in the Actions tab for any issues
3. Verify all pages and links work correctly

### Troubleshooting

If you encounter issues:

- **404 Errors**: Verify the `base` path in `docs/.vitepress/config.ts` is set to `/asn-api/`
- **Build Failures**: Check the Actions logs for specific error messages
- **Permission Errors**: Ensure the workflow has `pages: write` and `id-token: write` permissions

## Creating v1.0.0 Release

### Step 1: Push the Tag

A git tag for v1.0.0 has been created locally with a comprehensive release message. To push it to GitHub:

```bash
git push origin v1.0.0
```

**Note**: If you don't have permission to push tags, the repository administrator will need to do this after the PR is merged.

### Step 2: Create GitHub Release from Tag

Once the tag is pushed to GitHub:

1. Go to the repository on GitHub
2. Navigate to **Releases** → **"Draft a new release"**
3. Click **"Choose a tag"** and select `v1.0.0`
4. The release title and description should be auto-populated from the tag message
5. Review the release notes:

```markdown
# Release v1.0.0 - ASN Risk Intelligence Platform

This release marks the first stable version of the ASN Risk Intelligence Platform.

## Features

- ✅ Comprehensive ASN risk scoring with 30+ signals
- ✅ Real-time BGP telemetry processing from RIPE RIS
- ✅ Multi-source threat intelligence integration
- ✅ Production-ready REST API with authentication and rate limiting
- ✅ Interactive VitePress documentation deployed to GitHub Pages
- ✅ Advanced analytics including downstream risk and topology analysis
- ✅ Grafana dashboards for monitoring and visualization
- ✅ Docker-based deployment with PostgreSQL, ClickHouse, and Redis
- ✅ 365-day historical score tracking

## Documentation

- 📚 [Online Documentation](https://fabriziosalmi.github.io/asn-api/)
- 📖 [API Reference](https://fabriziosalmi.github.io/asn-api/api/)
- 🏗️ [Architecture Guide](https://fabriziosalmi.github.io/asn-api/architecture/)
- 🚀 [Quick Start Guide](https://fabriziosalmi.github.io/asn-api/guide/)

## Quick Start

```bash
git clone https://github.com/fabriziosalmi/asn-api.git
cd asn-api
docker-compose up --build
```

Access the services:
- API: http://localhost:8080/docs (API Key: `dev-secret`)
- Grafana: http://localhost:3000 (admin/admin)
- Documentation: https://fabriziosalmi.github.io/asn-api/
```

6. Click **"Publish release"**

### Alternative: Create Release via GitHub CLI

If you have GitHub CLI installed and authenticated:

```bash
gh release create v1.0.0 \
  --title "Release v1.0.0 - ASN Risk Intelligence Platform" \
  --notes "See the [documentation](https://fabriziosalmi.github.io/asn-api/) for complete feature details."
```

## Verification Checklist

After completing the setup:

- [ ] GitHub Pages is enabled with "GitHub Actions" as source
- [ ] Deployment workflow runs successfully
- [ ] Documentation is accessible at https://fabriziosalmi.github.io/asn-api/
- [ ] All documentation pages load correctly
- [ ] v1.0.0 tag is pushed to GitHub
- [ ] v1.0.0 release is created on GitHub
- [ ] Release includes comprehensive release notes

## Summary

This setup provides:

1. **Automated Documentation Deployment**: VitePress docs automatically deploy to GitHub Pages on every push to `main`
2. **Version 1.0.0 Release**: Formal release tag marking the first stable version
3. **Public Documentation**: Professional documentation site accessible to all users
4. **CI/CD Integration**: GitHub Actions workflow for continuous documentation deployment

## Support

For issues or questions:
- Check the [documentation](https://fabriziosalmi.github.io/asn-api/)
- Review workflow logs in the Actions tab
- Consult the [DEPLOYMENT.md](./DEPLOYMENT.md) guide
