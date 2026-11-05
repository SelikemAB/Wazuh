# Rendered by scripts/render-configs.sh -> wazuh.yml (git-ignored).
hosts:
  - default:
      url: "https://wazuh.manager"
      port: 55000
      username: "${API_WUI_USERNAME}"
      password: "${API_WUI_PASSWORD}"
      run_as: false
