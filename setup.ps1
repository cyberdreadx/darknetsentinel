# DarkNet Sentinel Setup Script
# Run this script to install all required dependencies

Write-Host "Setting up DarkNet Sentinel..." -ForegroundColor Green
Write-Host "Installing Python dependencies..." -ForegroundColor Yellow

# Check if pip is available
if (Get-Command pip -ErrorAction SilentlyContinue) {
    pip install -r requirements.txt
    Write-Host "Dependencies installed successfully!" -ForegroundColor Green
    Write-Host "You can now run the app with: streamlit run darknet_sentinel_app.py" -ForegroundColor Cyan
} else {
    Write-Host "Error: pip not found. Please install Python and pip first." -ForegroundColor Red
}

Write-Host "Setup complete!" -ForegroundColor Green
