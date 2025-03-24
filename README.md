# Guitar Practice Web App

A web application for guitarists to track their practice sessions, manage songs, and improve chord transitions.

## Features

- **Song Management**
  - Add, edit, and delete songs
  - Store chord progressions, strumming patterns, and notes
  - Track BPM and time signatures
  - Capo position tracking

- **Practice Tools**
  - One-minute chord change practice
  - Predefined chord pairs with difficulty levels
  - Practice session tracking
  - Progress monitoring

- **User Features**
  - User authentication
  - Personal song library
  - Practice history
  - Backup and restore functionality

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/stevencoutts/guitar-webapp.git
   cd guitar-webapp
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   Create a `.env` file in the project root with:
   ```
   SECRET_KEY=your-secret-key-here
   DATABASE_URL=sqlite:///instance/guitar.db
   ```

5. Initialize the database:
   ```bash
   flask db upgrade
   ```

6. Run the application:
   ```bash
   flask run
   ```

## Usage

1. Register a new account or log in
2. Add songs to your library
3. Use the chord changes practice tool to improve your transitions
4. Track your progress over time
5. Backup your data when needed

## Development

- Built with Flask
- Uses SQLite database
- Bootstrap 5 for styling
- Font Awesome icons

## License

This project is released under The Unlicense. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

If you encounter any issues or have questions, please open an issue on the GitHub repository. 