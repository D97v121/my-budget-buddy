def register_routes(app):
    @app.route('/some_route')
    def some_route():
        # Your route logic...
        return 'Hello, World!'
