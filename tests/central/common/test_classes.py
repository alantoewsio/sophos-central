"""Tests for central.common.classes."""

from central.common.classes import Admin, Admins, Role, Roles


def test_roles_get_role_by_id():
    r = Role({"id": "x", "name": "N", "type": "custom", "principalType": "user"})
    coll = Roles([r])
    assert coll.get_role_by_id("x") is r
    assert coll.get_role_by_id("missing") is None


def test_admins_get_admin_by_id():
    a = Admin(
        {
            "id": "a",
            "tenant": {"id": "t"},
            "users": [],
            "profile": {"name": "n", "email": "e@e"},
            "roleAssignments": [],
        }
    )
    coll = Admins([a])
    assert coll.get_admin_by_id("a") is a
    assert coll.get_admin_by_id("z") is None
