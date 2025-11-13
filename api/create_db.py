from index import db, app, User
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt(app)

with app.app_context():
    db.create_all()
    print("✅ Database created on Render!")

    # Create admin
    admin_pass = bcrypt.generate_password_hash("admin123").decode("utf-8")
    admin = User(username="admin", email="admin@vyatihar.com", password=admin_pass, is_admin=True)
    db.session.add(admin)
    db.session.commit()

    print("✅ Admin created: admin@vyatihar.com / admin123")
