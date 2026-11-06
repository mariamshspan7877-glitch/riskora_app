import os
from flask import Flask, render_template
from flask_login import LoginManager
from flask_wtf import CSRFProtect

from config import Config
from models import db, User
from routes import register_blueprints

login_manager = LoginManager()
csrf = CSRFProtect()


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    if test_config:
        app.config.from_mapping(test_config)

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["REPORT_FOLDER"], exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "warning"
    csrf.init_app(app)

    with app.app_context():
        db.create_all()

    register_blueprints(app)

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("404.html"), 404

    @app.errorhandler(413)
    def payload_too_large(_error):
        size_mb = app.config.get("MAX_UPLOAD_SIZE", 0) / (1024 * 1024)
        return (
            render_template(
                "error.html",
                title="Upload too large",
                message=f"The uploaded file exceeds the supported size limit of {size_mb:.1f} MB.",
            ),
            413,
        )

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
