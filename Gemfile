# frozen_string_literal: true
source "https://rubygems.org"

gem "jekyll", "~> 4.3.2"
gem "jekyll-theme-chirpy", "~> 7.2", ">= 7.2.4"

# Required plugins for the theme
group :jekyll_plugins do
  gem "jekyll-paginate"
  gem "jekyll-archives"
  gem "jekyll-sitemap"
  gem "jekyll-redirect-from"
end

gem "html-proofer", "~> 5.0", group: :test

platforms :mingw, :x64_mingw, :mswin, :jruby do
  gem "tzinfo", ">= 1", "< 3"
  gem "tzinfo-data"
  gem "wdm", "~> 0.2.0"
end

# Explicitly add missing standard libs for Ruby 3.4+
gem "csv"
gem "logger"
gem "base64"
