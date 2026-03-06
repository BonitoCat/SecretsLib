A library for storing, looking up and clearing secrets in your app.

Usage:
- Add SecretsLib.dll as a dependency in your project.
- Call SecretsManager.Initialize(string name) with a unique name for your app (E.g. username.your-app.secret).
- Call the StoreSecret, LookupSecret and ClearSecret methods as needed.
