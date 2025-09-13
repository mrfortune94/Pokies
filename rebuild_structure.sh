#!/usr/bin/env bash
set -e
echo "Rebuilding Android project structure..."

# Create directories
mkdir -p app/src/main/java/com/yourcompany/fortunateslotpenetration
mkdir -p app/src/main/res/layout
mkdir -p app/src/main/res/values
mkdir -p app/src/main/res/menu
mkdir -p app/src/main/res/xml

# Move files into place
mv -f app_build.gradle.kts app/build.gradle.kts
mv -f AndroidManifest.xml app/src/main/AndroidManifest.xml
mv -f MainActivity.kt app/src/main/java/com/yourcompany/fortunateslotpenetration/MainActivity.kt
mv -f activity_main.xml app/src/main/res/layout/activity_main.xml
mv -f strings.xml app/src/main/res/values/strings.xml
mv -f themes.xml app/src/main/res/values/themes.xml
mv -f menu_main.xml app/src/main/res/menu/menu_main.xml
mv -f network_security_config.xml app/src/main/res/xml/network_security_config.xml

echo "Structure rebuilt. Proceeding with build..."
