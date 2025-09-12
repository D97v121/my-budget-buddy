def register_routes(app):
    from .index_routes import index_bp
    app.register_blueprint(index_bp)
    from .plaid_routes import plaid_bp
    app.register_blueprint(plaid_bp)
    

    from app.routes.auth_routes import auth_bp
    from app.routes.data_routes import data_bp
    from app.routes.profile_routes import profile_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(data_bp)
    app.register_blueprint(profile_bp)
    from app.routes.tracking_routes import tracking_bp
    app.register_blueprint(tracking_bp)
    from app.routes.history_routes import history_bp
    app.register_blueprint(history_bp)
    from .settings_routes import settings_bp
    app.register_blueprint(settings_bp)

    from .transaction_routes import transaction_bp
    app.register_blueprint(transaction_bp)

    from .notes_routes import notes_bp
    app.register_blueprint(notes_bp)

    from .goals_routes import goals_bp
    app.register_blueprint(goals_bp)

    from .resources_routes import resources_bp
    app.register_blueprint(resources_bp)

    from .dev_routes import dev_bp
    app.register_blueprint(dev_bp)

    from .api_transactions import transactions_api
    app.register_blueprint(transactions_api)

    from .api_accounts import api_accounts
    app.register_blueprint(api_accounts)

    from .plaid_extra_features import plaid_extra_features
    app.register_blueprint(plaid_extra_features)

    from .cra_check_routes import cra_check
    app.register_blueprint(cra_check)  

    from .dashboard_routes import dashboard_routes
    app.register_blueprint(dashboard_routes, url_prefix="/dashboard")  

    from app.routes.admin_routes import admin_bp
    app.register_blueprint(admin_bp)

    from app.routes.nlp_api import nlp_api
    app.register_blueprint(nlp_api)
    from health import bp as health_bp
    app.register_blueprint(health_bp)


