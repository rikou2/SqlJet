# GitHub Setup Instructions

After creating your new GitHub repository, run these commands:

```bash
# Connect your local repository to GitHub
git remote add origin https://github.com/YOUR_USERNAME/SqlQ.git

# Push your local repository to GitHub
git push -u origin main
```

Replace `YOUR_USERNAME` with your GitHub username.

When prompted, enter your GitHub username and password or personal access token.

## Creating a Personal Access Token (if needed)

If password authentication fails, you might need to use a personal access token:

1. Go to GitHub → Settings → Developer settings → Personal access tokens → Generate new token
2. Give it a name (e.g., "SqlQ Project")
3. Select the "repo" scope
4. Click "Generate token"
5. Copy the token and use it as your password when pushing

## Using SSH Authentication (Alternative)

Alternatively, you can set up SSH authentication:

```bash
# Change the remote URL to use SSH
git remote set-url origin git@github.com:YOUR_USERNAME/SqlQ.git

# Push to GitHub
git push -u origin main
```
