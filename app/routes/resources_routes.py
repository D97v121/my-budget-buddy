from flask import Blueprint, render_template
from flask_login import login_required

resources_bp = Blueprint("resources", __name__)

@resources_bp.route('/resources', methods=["GET", "POST"])
@login_required
def resources():
    return render_template("resources.html")