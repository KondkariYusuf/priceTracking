        # Price Comparison Website

A Flask-based web application that allows users to compare prices across different online stores using the Google Shopping API.

## Features

- User registration and authentication
- Product search functionality
- Price comparison across multiple stores
- Responsive design using Bootstrap
- Secure password handling

## Installation

1. Clone the repository
2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file with your API key and secret key:
```
GOOGLE_SHOPPING_API_KEY=your_api_key
SECRET_KEY=your_secret_key
```

5. Run the application:
```bash
python app.py
```

6. Open your browser and navigate to `http://localhost:5000`

## Usage

1. Register for an account or login if you already have one
2. Use the search bar to look for products
3. Browse through the results to compare prices from different stores
4. Click on "View Deal" to visit the store's website

## Security Notes

- Never commit your `.env` file to version control
- Keep your API keys secure
- Regularly update your dependencies
