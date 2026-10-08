"""Authenticated API-only owner profile setup; credentials never enter source or logs."""

def deploy_owner_source(control, http, app_path, url):
    source, _ = http.request("GET", app_path + "/source")
    control.verify_devsy_app_source(source, url)
    wanted = control.owner_devsy_app_source(url)
    index = next(
        file["content"] for file in source["files"] if file["path"] == "index.ts"
    )
    if index.strip() != wanted.strip():
        files = [
            {
                "path": file["path"],
                "content": wanted if file["path"] == "index.ts" else file["content"],
            }
            for file in source["files"]
        ]
        http.request("POST", app_path + "/deploy", {"files": files})
    retained, _ = http.request("GET", app_path + "/source")
    control.verify_generated_source(retained, wanted, "Owner Devsy")
    return source


def connect_owner(http, prefix, app_id, token):
    app_path = prefix + "/apps/" + app_id
    profiles, _ = http.request("GET", app_path + "/profiles")
    matching = [p for p in profiles if p.get("name") == "Owner Devsy scope"]
    if len(matching) > 1:
        raise ValueError("Ambiguous owner profile; no credential changed.")
    if matching:
        profile = matching[0]
        if profile.get("accounts", {}).get("bridge"):
            return profile
    else:
        profile, _ = http.request(
            "POST",
            app_path + "/profiles",
            {
                "name": "Owner Devsy scope",
                "accounts": {},
                "idempotencyKey": "devsy-owner-scope-v1",
            },
        )
    connection, _ = http.request(
        "POST",
        app_path + "/connections",
        {"requirement": "bridge", "profile": profile["id"]},
    )
    http.request(
        "POST",
        prefix + "/connections/" + connection["id"] + "/submit",
        {
            "method": "apiKey",
            "label": "Private owner Devsy capability",
            "fields": {"token": token},
        },
    )
    result, _ = http.request("GET", app_path + "/profiles/" + profile["id"])
    return result
