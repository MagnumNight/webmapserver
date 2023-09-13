# GPS Visualization Tool

This server exists simply to be able to plot GPS points (currently only CSV) on a map without having to worry about who owns the data.

The live server runs on a Digital Ocean droplet that is encrypted. Additionally, no data is stored on the server, other than
the login credentials of the users.

## Prerequisites

Python 3.11

pip

Virtual environment (optional, but recommended)

## Getting Started

### Clone the Repository:

```
git clone [URL_OF_THE_REPOSITORY]
```

### Generate your own geoapify API key:

#### In map.html, update this with your API key:

```
L.tileLayer(
            'https://maps.geoapify.com/v1/tile/osm-bright/{z}/{x}/{y}.png?apiKey=your-API-key', {
                maxZoom: 19,
                attribution: '© Geoapify and © OpenStreetMap contributors'
            }).addTo(map);
```

### Navigate to the project directory:

```
cd path_to_directory
```

### Set Up a Virtual Environment (Recommended):

```
python -m venv venv

source venv/bin/activate  # On Windows use: venv\Scripts\activate
```

### Install Dependencies:

```
pip install -r requirements.txt
```

### Run the Flask app:

```
flask run
```

### Usage:

```
Navigate to the URL (typically http://127.0.0.1:5000/ if running locally).
Use the registration system to create an account.
Login using your credentials.
Navigate to settings to change your password.
```

### Security Practices:

```
Passwords are hashed using bcrypt.
Common passwords are checked against a list to ensure user password security.
Logging of failed login attempts including IP for audit purposes.
```

### Contributing:

```
Pull requests are welcome. 
For major changes, please open an issue first to discuss what you would like to change.
```

### License:

This project is licensed under the MIT License - please look at the LICENSE.txt file for details.
