from flask import Blueprint

main_bp = Blueprint('main', __name__)

@main_bp.route('/some_route')
def some_route():
    return 'Hello, World!'