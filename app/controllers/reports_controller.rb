require "prawn"

class ReportsController < ApplicationController
  before_action :set_report_data, only: [:generate, :download_pdf]

  def generate
    render template: "reports/report_template", layout: false
  end
  def download_pdf
    begin
      require 'prawn/table'
  
      logger.info "PDF generation started - #{Time.now}"
  
      # Create PDF with optimized layout
      pdf = Prawn::Document.new(
        page_size: "A4",
        page_layout: :portrait,
        margin: [40, 30, 40, 30], # Slightly narrower side margins
        info: {
          Title: "Threat Intelligence Report",
          Author: "Your Organization",
          CreationDate: Time.now
        }
      )
  
      # Color scheme
      primary_color = "2C3E50"
      secondary_color = "E74C3C"
      accent_color = "3498DB"
      light_gray = "F5F5F5"
      dark_gray = "333333"
  
      # Header with improved styling
      pdf.fill_color primary_color
      pdf.text "Threat Intelligence Report", size: 22, style: :bold, align: :center
      pdf.move_down 5
      pdf.stroke_horizontal_rule
      pdf.move_down 10
      pdf.fill_color dark_gray
      pdf.text "Generated: #{Time.now.strftime('%Y-%m-%d %H:%M')}", size: 10, align: :center
      pdf.move_down 20
  
      # Methodology section with improved table
      pdf.fill_color primary_color
      pdf.text "1. Methodology", size: 18, style: :bold
      pdf.move_down 10
      
      methodology_data = @report_data[:methodology].map do |task|
        [
          { content: task[:task].to_s.truncate(25), font_style: :bold },
          { content: task[:status].to_s.truncate(15), align: :center },
          task[:description].to_s.truncate(60),
          { content: task[:category].to_s.truncate(15), align: :center }
        ]
      end
      
      methodology_header = [
        { content: "Task", font_style: :bold, align: :center },
        { content: "Status", font_style: :bold, align: :center },
        { content: "Description", font_style: :bold, align: :center },
        { content: "Category", font_style: :bold, align: :center }
      ]
      
      pdf.table([methodology_header] + methodology_data,
                width: pdf.bounds.width,
                column_widths: { 
                  0 => pdf.bounds.width * 0.20,
                  1 => pdf.bounds.width * 0.15,
                  2 => pdf.bounds.width * 0.45,
                  3 => pdf.bounds.width * 0.20 
                },
                header: true) do
        cells.padding = [4, 6, 4, 6] # More horizontal padding
        cells.borders = [:bottom]
        cells.border_width = 0.5
        cells.border_color = light_gray
        row(0).background_color = primary_color
        row(0).text_color = "FFFFFF"
        row(0).borders = [:bottom]
        row(0).border_width = 1
        row(0).border_color = dark_gray
        cells.style do |c|
          c.overflow = :shrink_to_fit
          c.min_font_size = 8
          c.valign = :center # Vertical center alignment
        end
      end
      pdf.move_down 25
  
      # Enhanced Domain DNS Intelligence section
      pdf.fill_color primary_color
      pdf.text "2. Domain DNS Intelligence", size: 18, style: :bold
      pdf.move_down 15
  
      # Domain Summary
      pdf.fill_color secondary_color
      pdf.text "Domain Summary", size: 14, style: :bold
      pdf.move_down 5
      
      domain_summary = [
        ["Total Domains", @report_data[:findings][:domain_dns_intelligence][:domains]],
        ["WHOIS Note", @report_data[:findings][:domain_dns_intelligence][:whois_note]]
      ]
      
      pdf.table(domain_summary,
                width: pdf.bounds.width,
                column_widths: {0 => 120, 1 => pdf.bounds.width - 120},
                cell_style: {borders: [], padding: [2, 5, 2, 5]}) do
        column(0).font_style = :bold
        column(0).text_color = dark_gray
      end
      pdf.move_down 15
  
      # DNS Records Tables - each record type gets its own formatted table
      dns_records = @report_data[:findings][:domain_dns_intelligence][:dns_records_summary]
      
      # NS Records
      if dns_records[:ns_records_info].any?
        pdf.fill_color secondary_color
        pdf.text "Name Server (NS) Records", size: 14, style: :bold
        pdf.move_down 5
        
        ns_data = dns_records[:ns_records_info].map { |r| [r[:name], r[:ip]] }
        pdf.table([["Name Server", "IP Address"]] + ns_data,
                  width: pdf.bounds.width,
                  column_widths: {0 => pdf.bounds.width * 0.4, 1 => pdf.bounds.width * 0.6},
                  header: true) do
          row(0).background_color = primary_color
          row(0).text_color = "FFFFFF"
          cells.borders = [:bottom]
          cells.border_color = light_gray
          cells.padding = [3, 5, 3, 5]
        end
        pdf.move_down 15
      end
  
      # A Records
      if dns_records[:a_records_info].any?
        pdf.fill_color secondary_color
        pdf.text "Address (A) Records", size: 14, style: :bold
        pdf.move_down 5
        
        a_data = dns_records[:a_records_info].map { |r| [r[:name], r[:ip]] }
        pdf.table([["Hostname", "IP Address"]] + a_data,
                  width: pdf.bounds.width,
                  column_widths: {0 => pdf.bounds.width * 0.4, 1 => pdf.bounds.width * 0.6},
                  header: true) do |table|
          table.row(0).background_color = primary_color
          table.row(0).text_color = "FFFFFF"
          table.cells.borders = [:bottom]
          table.cells.border_color = light_gray
          table.cells.padding = [3, 5, 3, 5]
        end
        pdf.move_down 15
      end
  
      # MX Records
      if dns_records[:mx_records_info].any?
        pdf.fill_color secondary_color
        pdf.text "Mail Exchange (MX) Records", size: 14, style: :bold
        pdf.move_down 5
        
        mx_data = dns_records[:mx_records_info].map { |r| [r[:name], r[:priority], r[:target]] }
        pdf.table([["Domain", "Priority", "Mail Server"]] + mx_data,
                  width: pdf.bounds.width,
                  column_widths: {0 => pdf.bounds.width * 0.3, 1 => pdf.bounds.width * 0.2, 2 => pdf.bounds.width * 0.5},
                  header: true) do
          row(0).background_color = primary_color
          row(0).text_color = "FFFFFF"
          cells.borders = [:bottom]
          cells.border_color = light_gray
          cells.padding = [3, 5, 3, 5]
          column(1).align = :center # Center priority numbers
        end
        pdf.move_down 15
      end
  
      # WHOIS Information
      if @report_data[:findings][:domain_dns_intelligence][:whois_info_shown].any?
        pdf.fill_color primary_color
        pdf.text "WHOIS Information", size: 16, style: :bold
        pdf.move_down 10
        
        whois_data = @report_data[:findings][:domain_dns_intelligence][:whois_info_shown].map do |w|
          [
            w[:domain_name],
            w[:registrar],
            w[:created_at],
            w[:updated_at],
            w[:expires_at]
          ]
        end
        
        pdf.table([
          ["Domain", "Registrar", "Created", "Updated", "Expires"]
        ] + whois_data,
        width: pdf.bounds.width,
        header: true) do
          row(0).background_color = primary_color
          row(0).text_color = "FFFFFF"
          cells.borders = [:bottom]
          cells.border_color = light_gray
          cells.padding = [3, 4, 3, 4]
          cells.style { |c| c.overflow = :shrink_to_fit; c.min_font_size = 7 }
          column(2..4).align = :center # Center dates
        end
        pdf.move_down 20
      end
  
      # Data Leaks section with improved formatting
      pdf.fill_color primary_color
      pdf.text "3. Data Leaks and Breaches", size: 18, style: :bold
      pdf.move_down 10
      
      if @report_data[:findings][:data_leaks_and_breaches][:logstealer_leaks][:shown].any?
        pdf.fill_color secondary_color
        pdf.text "Logstealer Leaks", size: 14, style: :bold
        pdf.move_down 5
        
        leaks_data = @report_data[:findings][:data_leaks_and_breaches][:logstealer_leaks][:shown].map do |leak|
          leak.map { |item| item.to_s.truncate(25) }
        end
        
        pdf.table([
          ["Date", "Source", "Type", "Details"]
        ] + leaks_data,
        width: pdf.bounds.width,
        header: true) do
          row(0).background_color = primary_color
          row(0).text_color = "FFFFFF"
          cells.borders = [:bottom]
          cells.border_color = light_gray
          cells.padding = [3, 4, 3, 4]
          cells.style { |c| c.overflow = :shrink_to_fit; c.min_font_size = 7 }
          column(0).width = 80 # Fixed width for date column
        end
      else
        pdf.text "No logstealer leaks found", size: 12, style: :italic
      end
  
      # Footer with improved styling
      pdf.repeat(:all) do
        pdf.bounding_box([pdf.bounds.left, pdf.bounds.bottom + 15], width: pdf.bounds.width) do
          pdf.stroke_horizontal_rule
          pdf.move_down 3
          pdf.text "Confidential - Page #{pdf.page_number} of #{pdf.page_count}", 
                   size: 8, 
                   align: :right,
                   color: dark_gray
        end
      end
  
      # Generate and send PDF
      pdf_path = Rails.root.join('tmp', "threat_report_#{Time.now.strftime('%Y%m%d_%H%M')}.pdf")
      pdf.render_file(pdf_path)
  
      send_file pdf_path,
                filename: "threat_intelligence_report.pdf",
                type: 'application/pdf',
                disposition: 'inline'
  
    rescue => e
      logger.error "PDF ERROR: #{e.message}\n#{e.backtrace.join("\n")}"
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