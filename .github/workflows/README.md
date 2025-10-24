# GitHub Actions Workflows for PyPI Publishing

This directory contains GitHub Actions workflows for automatically publishing the diffrays package to PyPI.

## Workflows

### 1. `publish.yml` - Production PyPI Publishing
- **Triggers**: 
  - When a GitHub release is published
  - Manual trigger via GitHub Actions UI
- **Purpose**: Publishes the package to the official PyPI repository
- **Required Secret**: `PYPI_API_TOKEN`

### 2. `testpypi.yml` - TestPyPI Publishing
- **Triggers**: 
  - Push to `main` or `develop` branches
  - Manual trigger via GitHub Actions UI
- **Purpose**: Publishes the package to TestPyPI for testing
- **Required Secret**: `TEST_PYPI_API_TOKEN`

## Setup Instructions

### For Production PyPI Publishing:

1. **Create PyPI API Token**:
   - Go to [PyPI](https://pypi.org) and log in
   - Navigate to Account Settings → API tokens
   - Create a new API token (scope: "Entire account" or project-specific)
   - Copy the token (starts with `pypi-`)

2. **Add GitHub Secret**:
   - Go to your GitHub repository
   - Settings → Secrets and variables → Actions
   - Click "New repository secret"
   - Name: `PYPI_API_TOKEN`
   - Value: Your PyPI API token

3. **Publishing Process**:
   - Update version in `pyproject.toml`
   - Commit and push changes
   - Create a GitHub release with the same version number
   - The workflow will automatically publish to PyPI

### For TestPyPI Publishing:

1. **Create TestPyPI Account**:
   - Go to [test.pypi.org](https://test.pypi.org)
   - Create an account (can be same as PyPI account)

2. **Create TestPyPI API Token**:
   - Log in to TestPyPI
   - Go to Account Settings → API tokens
   - Create a new API token
   - Copy the token

3. **Add GitHub Secret**:
   - Add `TEST_PYPI_API_TOKEN` secret in GitHub repository settings
   - Value: Your TestPyPI API token

## Usage

### Manual Publishing
Both workflows support manual triggering:
1. Go to GitHub repository → Actions tab
2. Select the desired workflow
3. Click "Run workflow"

### Version Management
- Update the version in `pyproject.toml` before creating a release
- The version in the release tag should match the version in `pyproject.toml`
- Example: If `pyproject.toml` has `version = "1.6"`, create a release with tag `v1.6`

## Security Notes
- Never commit API tokens to the repository
- Use repository secrets for storing sensitive information
- API tokens provide better security than username/password authentication
