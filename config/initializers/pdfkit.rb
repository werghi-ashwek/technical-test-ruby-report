PDFKit.configure do |config|
  config.wkhtmltopdf = if Rails.env.production?
                         '/usr/bin/wkhtmltopdf'
                       else
                         '"C:/Program Files/wkhtmltopdf/bin/wkhtmltopdf.exe"'
                       end
  
  config.default_options = {
    page_size: 'Letter',
    print_media_type: true,
    encoding: 'UTF-8',
    javascript_delay: 1000,
    debug_javascript: true,
    quiet: false
  }
end