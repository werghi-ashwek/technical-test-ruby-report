Rails.application.routes.draw do
  # Route for generating the HTML version of the report
  get "reports/generate", to: "reports#generate"
  # Route for downloading the PDF version of the report
  get 'reports/download_pdf' => 'reports#download_pdf', as: 'download_report'
  # Set root path to the HTML view
  root "reports#generate"
end
