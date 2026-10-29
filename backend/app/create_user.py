"""Create a user from the command line:  python -m app.create_user aayan --role admin"""
import argparse
import getpass
import sys

from sqlmodel import Session, select

from app.database import engine
from app.models import ROLES, User
from app.security import hash_password


def main():
    parser = argparse.ArgumentParser(description="Create a SentinelWatch user")
    parser.add_argument("username")
    parser.add_argument("--role", choices=ROLES, default="analyst")
    args = parser.parse_args()

    password = getpass.getpass("Password (min 12 characters): ")
    if len(password) < 12:
        sys.exit("Password must be at least 12 characters.")
    if password != getpass.getpass("Confirm password: "):
        sys.exit("Passwords do not match.")

    with Session(engine) as session:
        if session.exec(select(User).where(User.username == args.username)).first():
            sys.exit(f"User '{args.username}' already exists.")
        session.add(
            User(
                username=args.username,
                password_hash=hash_password(password),
                role=args.role,
            )
        )
        session.commit()
    print(f"Created {args.role} '{args.username}'.")


if __name__ == "__main__":
    main()
