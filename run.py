"""
app.py

This module initializes and configures a Flask application.

Description: This module creates a Flask app using the create_app() factory func.
It configures the app based on the environment specified by
the FLASK_ENV environment variable.
The app's configuration can be set using the config.py module.

Functions:
- create_app(): Factory function to create and configure the Flask application.
"""
import os

from flask import Flask
from flask_cors import CORS
from config.config import TestingConfig, ProductionConfig
from models import initialize_database
from views.views import views_bp


# Your existing route definitions and functions...

def create_app():
    """
        create_app() -> Flask

        Factory function to create and configure the Flask application.

        Returns:
        Flask: Configured Flask application instance.
        """
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['FLASK_ENV'] = os.getenv('FLASK_ENV')
    if app.config['FLASK_ENV'] == 'testing':
        app.config.from_object(TestingConfig)
        app.config['DEBUG'] = True
    elif app.config['FLASK_ENV'] == 'production':
        app.config.from_object(ProductionConfig)
        app.config['DEBUG'] = False

    # Initialize database
    app.register_blueprint(views_bp)
    with app.app_context():
        initialize_database()

    CORS(app)
    return app


if __name__ == "__main__":
    app = create_app()
    app.run()
