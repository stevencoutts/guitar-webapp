# Guitar Song Manager

A web application for managing guitar songs, including time signatures, chord progressions, and strumming patterns.

## Features

- User authentication (register/login)
- Add and view guitar songs
- Store time signatures, chord progressions, and strumming patterns
- Modern, responsive UI using Bootstrap

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd guitar-webapp
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Linux/Mac
# or
.\venv\Scripts\activate  # On Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
export SECRET_KEY='your-secret-key-here'  # On Linux/Mac
# or
set SECRET_KEY=your-secret-key-here  # On Windows
```

5. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
```

## Running the Application

1. Development server:
```bash
python app.py
```

2. Production server (using gunicorn):
```bash
gunicorn app:app
```

## Nginx Configuration

Add the following configuration to your Nginx server:

```nginx
server {
    listen 80;
    server_name guitar.couttsnet.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static {
        alias /path/to/your/app/static;
    }
}
```

## Security Considerations

1. Change the `SECRET_KEY` in production
2. Use HTTPS in production
3. Set up proper file permissions for the database and uploads directory
4. Regularly backup the database

## License

This project is licensed under the MIT License - see the LICENSE file for details. 