"""This is the main program that will run the whole webserver"""

from website import create_app

app = create_app()

if __name__ == "__main__":
    app.run()
