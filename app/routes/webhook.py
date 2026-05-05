from flask import request, jsonify, Blueprint

index_bp = Blueprint('index', __name__)

@index_bp.route('/webhook', methods=['POST'])
def handle_webhook():
    data = request.json
    print("Received webhook:", data)  # Log the webhook data
    return jsonify({"status": "success"}), 200