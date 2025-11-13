from api.index import db, app, User
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt(app)

with app.app_context():
    print("🔧 Creating database...")
    db.create_all()

    # Check if admin exists
    admin = User.query.filter_by(email="admin@vyatihar.com").first()

    if not admin:
        print("👨‍💼 Creating admin user...")
        admin_pass = bcrypt.generate_password_hash("admin123").decode("utf-8")
        admin = User(
            username="admin",
            email="admin@vyatihar.com",
            password=admin_pass,
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin user created!")
    else:
        print("ℹ️ Admin already exists.")

    print("✅ Database setup completed!")
