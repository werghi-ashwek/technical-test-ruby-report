Rails.application.routes.draw do
  get "up" => "rails/health#show", as: :rails_health_check

  get "reports/generate", to: "reports#generate"
  root "reports#generate"
end
