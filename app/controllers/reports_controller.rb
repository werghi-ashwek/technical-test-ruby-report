require "pdfkit"

class ReportsController < ApplicationController
  before_action :set_report_data, only: [:generate, :download_pdf]

  def generate
    render template: "reports/report_template", layout: false
  end

  def download_pdf
    begin
      # 1. Debug request
      logger.info "PDF generation started - #{Time.now}"
      
      # 2. Render HTML
      html = render_to_string(
        template: "reports/report_template",
        layout: false,
        locals: { report_data: @report_data }
      )
      
      # 3. Save debug files
      debug_dir = Rails.root.join('tmp/pdf_debug')
      FileUtils.mkdir_p(debug_dir)
      
      html_path = debug_dir.join('debug.html')
      File.write(html_path, html)
      logger.info "Debug HTML saved to: #{html_path}"
      
      # 4. Configure PDFKit
      kit = PDFKit.new(html,
        page_size: 'Letter',
        print_media_type: true,
        encoding: 'UTF-8',
        disable_javascript: false,
        javascript_delay: 2000,
        debug_javascript: true,
        quiet: false
      )
      
      # 5. Windows-specific configuration
      exe_path = 'C:/Program Files/wkhtmltopdf/bin/wkhtmltopdf.exe'
      unless File.exist?(exe_path)
        raise "wkhtmltopdf not found at #{exe_path}"
      end
      kit.configuration.wkhtmltopdf = exe_path
      
      # 6. Capture errors
      error_path = debug_dir.join('errors.log')
      kit.stderr = File.open(error_path, 'w')
      
      # 7. Generate PDF
      logger.info "Starting PDF generation..."
      pdf = kit.to_pdf
      logger.info "PDF generated successfully (#{pdf.size} bytes)"
      
      # 8. Verify PDF
      if pdf.size < 1024
        error_content = File.read(error_path) rescue "No error log found"
        raise "PDF generation failed. Errors:\n#{error_content}"
      end
      
      # 9. Send PDF with proper headers
      response.headers['Content-Length'] = pdf.size.to_s
      send_data pdf,
                filename: "report_#{Time.now.to_i}.pdf",
                type: 'application/pdf',
                disposition: 'inline'
      
    rescue => e
      logger.error "PDF ERROR: #{e.message}\n#{e.backtrace.join("\n")}"
      
      # Return error response that's visible to user
      render plain: "PDF Generation Failed: #{e.message}", status: 500
    end
  end

  private

  def set_report_data
    @report_data = {
      title: "Threat Intelligence Report",
      created_at: Time.current,
      updated_at: Time.current,
      executive_summary: executive_summary,
      report_metadata: report_metadata,
      methodology: methodology,
      findings: findings
    }.with_indifferent_access
  end

  def executive_summary
    {
      overview: "This report analyzes potential cyber threats targeting key domains within the organization.",
      targets_scope: "Domain A, Domain B, Domain C",
      high_level_findings: "Multiple vulnerabilities discovered in the external facing systems."
    }.with_indifferent_access
  end

  def report_metadata
    {
      report_version: "1.0.0",
      generated_by: "Security Team",
      generated_at: Time.current
    }.with_indifferent_access
  end

  def methodology
    [
      { task: "DNS Record Enumeration", status: "Completed", description: "Enumerating DNS records for the domain.", category: "Domain & DNS Intelligence" }.with_indifferent_access,
      { task: "Logstealers Search", status: "Ongoing", description: "Searching for logstealers related to the target.", category: "Leak Detection" }.with_indifferent_access,
      { task: "Subdomain Enumeration", status: "Completed", description: "Scanning for subdomains in the target network.", category: "Discovery" }.with_indifferent_access
    ]
  end

  def findings
    {
      domain_dns_intelligence: domain_dns_intelligence,
      data_leaks_and_breaches: data_leaks_and_breaches
    }.with_indifferent_access
  end

  def domain_dns_intelligence
    {
      domains: 5,
      dns_records_summary: dns_records_summary,
      whois_info_shown: whois_info_shown,
      whois_note: "WHOIS data collected from public registries"
    }.with_indifferent_access
  end

  def dns_records_summary
    {
      ns_records_info: [
        { name: "ns1.example.com", ip: "192.0.2.1" },
        { name: "ns2.example.com", ip: "192.0.2.2" }
      ],
      a_records_info: [
        { name: "example.com", ip: "203.0.113.1" },
        { name: "www.example.com", ip: "203.0.113.1" }
      ],
      mx_records_info: [
        { name: "example.com", priority: 10, target: "mail1.example.com" },
        { name: "example.com", priority: 20, target: "mail2.example.com" }
      ],
      txt_records_info: [
        { name: "example.com", content: "v=spf1 include:_spf.example.com ~all" }
      ],
      cname_records_info: [
        { name: "shop.example.com", target: "stores.example.com" }
      ]
    }.with_indifferent_access
  end

  def whois_info_shown
    [
      {
        domain_name: "example.com",
        registrar: "Some Registrar",
        created_at: "2022-01-01",
        updated_at: "2022-06-15",
        expires_at: "2023-01-01"
      },
      {
        domain_name: "example.net",
        registrar: "Another Registrar",
        created_at: "2022-02-01",
        updated_at: "2022-07-20",
        expires_at: "2023-02-01"
      }
    ].map(&:with_indifferent_access)
  end

  def data_leaks_and_breaches
    {
      logstealer_leaks: logstealer_leaks,
      public_leaks: public_leaks,
      combo_leaks: combo_leaks,
      summary: {
        total_leaks: logstealer_leaks[:total] + public_leaks[:total] + combo_leaks[:total],
        last_updated: Time.current
      }
    }.with_indifferent_access
  end

  def logstealer_leaks
    {
      total: 3,
      shown: [
        ["user1@example.com", "password123", "http://example.com", "2021"],
        ["user2@example.com", "password456", "http://example.org", "2020"],
        ["user3@example.com", "password789", "http://example.net", "2022"]
      ],
      note: "These credentials were exposed by malware targeting user data.",
      metadata: {
        source: "Malware analysis",
        confidence: "High"
      }
    }.with_indifferent_access
  end

  def public_leaks
    {
      total: 2,
      shown: [
        ["example_breach.com", "breachuser@example.com", "breachpassword", "2019"],
        ["anotherbreach.com", "anotheruser@example.com", "anotherpassword", "2018"]
      ],
      note: "These credentials were leaked through public breach lists.",
      metadata: {
        sources: ["HaveIBeenPwned", "BreachDirectory"],
        confidence: "Medium"
      }
    }.with_indifferent_access
  end

  def combo_leaks
    {
      total: 1,
      shown: [
        ["comboleak.com", "combo_user@example.com", "combo_password", "2021"]
      ],
      note: "Combo list leaks with combined username and password data.",
      metadata: {
        source: "Dark web monitoring",
        confidence: "Low"
      }
    }.with_indifferent_access
  end
end