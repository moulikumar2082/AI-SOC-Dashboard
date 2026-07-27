from app import create_app

app = create_app()

# Expose WSGI handler for Vercel
if __name__ == '__main__':
    app.run()
