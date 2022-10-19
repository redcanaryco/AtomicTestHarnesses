#!/usr/bin/osascript -l JavaScript
app = Application.currentApplication();
app.includeStandardAdditions = true;
app.systemInfo().shortUserName;