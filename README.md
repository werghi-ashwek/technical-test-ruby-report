#  Threat Intelligence PDF Reporter

A simple Rails application to generate PDF reports from threat intelligence data.

## Quick Start

1. **Clone the repository**:
   ```bash
   git clone https://github.com/werghi-ashwek/technical-test-ruby-report.git
   cd technical-test-report-generator
## Install dependencies:

bash
bundle install
## Start the server:

bash
rails server
Access the app in your browser:

http://localhost:3000/reports/generate
## Routes
The application has two main routes:

GET /reports/generate - HTML preview of the report

GET /reports/download_pdf - Generates and downloads the PDF report

## Dependencies
Ruby 3.x

Rails 7.x

## Prawn gem for PDF generation:

ruby
gem 'prawn'
gem 'prawn-table'

## Customization
Edit these files to modify the report:

app/controllers/reports_controller.rb - Report content and PDF formatting

app/views/reports/report_template.html.erb - HTML template
