from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models import AuditEvent


def register(client: TestClient, email: str):
    response = client.post("/auth/register", json={
        "email": email,
        "password": "Correct-Horse-Battery-42",
        "name": email.split("@")[0],
    })
    assert response.status_code == 201


def test_document_ids_do_not_grant_cross_organization_access(tmp_path, monkeypatch):
    import app.main as main

    monkeypatch.setattr(main, "FILE_ROOT", tmp_path)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    with TestClient(app) as first_client, TestClient(app) as second_client:
        rejected = first_client.post(
            "/auth/register",
            json={"email": "attacker@example.com", "password": "Correct-Horse-Battery-42", "name": "Attacker"},
            headers={"Origin": "https://attacker.example"},
        )
        assert rejected.status_code == 403
        register(first_client, "owner@alpha.example.com")
        first_org = first_client.post("/organizations", json={"name": "Alpha Workspace"}).json()
        created = first_client.post(
            f"/organizations/{first_org['id']}/documents",
            data={"title": "Plan confidentiel"},
            files={"file": ("plan.txt", b"alpha-only", "text/plain")},
        )
        assert created.status_code == 201
        document_id = created.json()["id"]

        register(second_client, "owner@beta.example.com")
        second_org = second_client.post("/organizations", json={"name": "Beta Workspace"}).json()

        assert first_client.get(f"/documents/{document_id}").status_code == 200
        assert second_client.get(f"/documents/{document_id}").status_code == 404
        assert second_client.get(f"/documents/{document_id}/download").status_code == 404
        assert second_client.get(f"/organizations/{first_org['id']}/documents").status_code == 404

        beta_document = second_client.post(
            f"/organizations/{second_org['id']}/documents",
            data={"title": "Beta document"},
            files={"file": ("beta.txt", b"beta-only", "text/plain")},
        ).json()
        assert first_client.get(f"/documents/{beta_document['id']}").status_code == 404
        second_user_id = second_client.get("/auth/me").json()["user"]["id"]
        with SessionLocal() as db:
            denial_types = {
                event.event_type for event in db.query(AuditEvent).filter(
                    AuditEvent.actor_id == second_user_id,
                    AuditEvent.result == "failure",
                ).all()
            }
        assert "authorization.document.denied" in denial_types
        assert "authorization.organization.denied" in denial_types
        assert first_client.post("/auth/logout").status_code == 200
        assert first_client.get("/auth/me").status_code == 401

    Base.metadata.drop_all(bind=engine)


def test_shared_document_requires_membership_and_respects_read_permission(tmp_path, monkeypatch):
    import app.main as main

    monkeypatch.setattr(main, "FILE_ROOT", tmp_path)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    with TestClient(app) as owner_client, TestClient(app) as member_client:
        register(owner_client, "owner@workspace.example.com")
        organization = owner_client.post("/organizations", json={"name": "Shared Workspace"}).json()
        document = owner_client.post(
            f"/organizations/{organization['id']}/documents",
            data={"title": "Shared notes"},
            files={"file": ("notes.txt", b"shared text", "text/plain")},
        ).json()
        invitation = owner_client.post(
            f"/organizations/{organization['id']}/invitations",
            json={"email": "member@workspace.example.com", "role": "member"},
        ).json()

        register(member_client, "member@workspace.example.com")
        accepted = member_client.post("/invitations/accept", json={"token": invitation["token"]})
        assert accepted.status_code == 200
        assert member_client.get(f"/documents/{document['id']}").status_code == 404

        shared = owner_client.put(
            f"/documents/{document['id']}/shares",
            json={"user_id": member_client.get("/auth/me").json()["user"]["id"], "permission": "read"},
        )
        assert shared.status_code == 200
        assert member_client.get(f"/documents/{document['id']}").status_code == 200
        assert member_client.get(f"/documents/{document['id']}/download").status_code == 200
        assert member_client.patch(
            f"/documents/{document['id']}",
            json={"title": "Changed", "description": ""},
        ).status_code == 404

        Base.metadata.drop_all(bind=engine)


def test_synthetic_demo_account_can_sign_in(tmp_path, monkeypatch):
    import app.main as main

    monkeypatch.setattr(main, "FILE_ROOT", tmp_path)
    monkeypatch.setenv("SEED_DEMO", "true")
    Base.metadata.drop_all(bind=engine)

    with TestClient(app) as client:
        response = client.post("/auth/login", json={
            "email": "demo@docuvault.example.com",
            "password": "DemoVault2026!",
        })
        assert response.status_code == 200
        organizations = client.get("/organizations").json()["organizations"]
        assert organizations[0]["name"] == "Atelier Horizon"
        documents = client.get(f"/organizations/{organizations[0]['id']}/documents").json()["documents"]
        assert documents[0]["title"] == "Guide de bienvenue"

    Base.metadata.drop_all(bind=engine)
