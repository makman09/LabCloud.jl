# CloudTrail audit analysis — full visual definition as code. This is the editable
# source of truth for the dashboard's visuals; edit here and `terraform apply` to
# change what the dashboard shows (then bump version_description in
# quicksight_dashboard.tf to republish).
#
# Structure — five themed sheets so the board reads like an analyst would work it:
#   1. Overview        operational health: volume, error count, service/region/read-write mix
#   2. Security        threat hunting: denials, error codes, root/no-MFA, IAM+KMS changes,
#                      odd user-agents, activity-by-hour heatmap (off-hours detection)
#   3. PHI Data Access HIPAA evidence: object-level Get/Put/Delete on research-* buckets,
#                      who-accessed-what-when, access by bucket/principal, deletions
#   4. Customers       per-customer activity, trend, data-access detail, error summary
#   5. Source IP Access source-IP × time of S3 activity for the two scoped-credential
#                      paths: LabCustomer→research-* and LabVendor→caucell-*-landing.
#                      Per block: unique IPs, top IPs, IP×hour heatmap, who/where/when table,
#                      and a geo point-map of source-IP origin (GeoLite2 enrichment, approx)
#   6. NAS Access      on-prem Synology file events (own dataset, synology_audit.tf):
#                      volume, action mix, top users/paths, recent-events detail
#
# Two calculated fields are defined below (event_hour, mfa_status). Their expressions
# use the QuickSight expression language and are NOT checked by `terraform validate`
# (it only validates that they're strings) — they are verified at `apply`/refresh time.
#
# Regenerate baseline (if ever needed):
#   aws quicksight describe-analysis-definition --aws-account-id <acct> \
#     --analysis-id d8e53ba4-1420-4706-b0f7-2804d03c1ebc --output json > def.json
#   python3 qs_json_to_hcl.py def.json

locals {
  audit_dataset = "CloudTrail Audit Dashboard"

  # Source-IP sheet visual sets, kept here so the per-condition filter groups that
  # scope each block (see fg-ip-customer-* / fg-ip-vendor-* below) stay in sync.
  ip_customer_visuals = ["ip-cust-kpi-ips", "ip-cust-bar-ip", "ip-cust-heat-hour", "ip-cust-tbl-detail", "ip-cust-geo"]
  ip_vendor_visuals   = ["ip-vend-kpi-ips", "ip-vend-bar-ip", "ip-vend-heat-hour", "ip-vend-tbl-detail", "ip-vend-geo"]

  # Event-name groupings reused across filter groups, kept here so the security and
  # PHI sheets stay in sync with one edit.
  s3_object_events  = ["GetObject", "PutObject", "DeleteObject", "HeadObject", "CopyObject"]
  iam_kms_events    = ["CreateUser", "DeleteUser", "CreateAccessKey", "DeleteAccessKey", "UpdateAccessKey", "AttachUserPolicy", "DetachUserPolicy", "PutUserPolicy", "CreateRole", "DeleteRole", "AttachRolePolicy", "CreatePolicy", "DeletePolicy", "CreateKey", "DisableKey", "ScheduleKeyDeletion", "PutKeyPolicy", "RevokeGrant", "CreateGrant", "DeleteAlias"]
  bucket_cfg_events = ["PutBucketPolicy", "PutBucketAcl", "PutBucketPublicAccessBlock", "DeleteBucketPolicy", "PutEncryptionConfiguration", "PutBucketVersioning"]
}

resource "aws_quicksight_analysis" "audit" {
  aws_account_id = var.account_id
  analysis_id    = "d8e53ba4-1420-4706-b0f7-2804d03c1ebc"
  name           = "CloudTrail Audit Dashboard analysis"
  theme_arn      = "arn:aws:quicksight::aws:theme/NITRO"

  definition {
    data_set_identifiers_declarations {
      identifier   = "CloudTrail Audit Dashboard"
      data_set_arn = aws_quicksight_data_set.audit_dashboard.arn
    }

    data_set_identifiers_declarations {
      identifier   = "Synology NAS Access"
      data_set_arn = aws_quicksight_data_set.synology_access.arn
    }

    # ── Calculated fields (runtime-verified, not validate-verified) ──────────
    calculated_fields {
      data_set_identifier = "CloudTrail Audit Dashboard"
      name                = "event_hour"
      expression          = "ifelse(extract('HH', {event_ts}) < 10, concat('0', toString(extract('HH', {event_ts}))), toString(extract('HH', {event_ts})))"
    }
    calculated_fields {
      data_set_identifier = "CloudTrail Audit Dashboard"
      name                = "mfa_status"
      expression          = "ifelse(isNull({mfa_used}), 'Unknown', ifelse({mfa_used} = 'true', 'MFA Present', 'No MFA'))"
    }

    # ════════════════════════════════════════════════════════════════════════
    # SHEET 1 — OVERVIEW
    # ════════════════════════════════════════════════════════════════════════
    sheets {
      sheet_id = "overview"
      name     = "Overview"

      filter_controls {
        date_time_picker {
          filter_control_id = "ctl-ov-daterange"
          source_filter_id  = "f-ov-daterange"
          title             = "Date range"
          type              = "DATE_RANGE"
          display_options {
            date_time_format = "YYYY-MM-DD"
            title_options {
              visibility = "VISIBLE"
              font_configuration {}
            }
          }
        }
      }

      visuals {
        kpi_visual {
          visual_id = "ov-kpi-total"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Total Events</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              trend_groups {
                date_dimension_field {
                  field_id = "ov-kpi-total.trend"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "event_ts"
                  }
                  date_granularity = "DAY"
                  hierarchy_id     = "ov-kpi-total.trend"
                }
              }
              values {
                date_measure_field {
                  field_id = "ov-kpi-total.value"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "event_ts"
                  }
                  aggregation_function = "COUNT"
                }
              }
            }
            kpi_options {
              primary_value_display_type = "ACTUAL"
              sparkline {
                visibility         = "VISIBLE"
                tooltip_visibility = "HIDDEN"
                type               = "LINE"
              }
            }
          }
          column_hierarchies {
            date_time_hierarchy {
              hierarchy_id = "ov-kpi-total.trend"
            }
          }
        }
      }

      visuals {
        kpi_visual {
          visual_id = "ov-kpi-failed"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Failed Events</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              trend_groups {
                date_dimension_field {
                  field_id = "ov-kpi-failed.trend"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "event_ts"
                  }
                  date_granularity = "DAY"
                  hierarchy_id     = "ov-kpi-failed.trend"
                }
              }
              values {
                numerical_measure_field {
                  field_id = "ov-kpi-failed.value"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "is_error"
                  }
                  aggregation_function {
                    simple_numerical_aggregation = "SUM"
                  }
                }
              }
            }
            kpi_options {
              primary_value_display_type = "ACTUAL"
              sparkline {
                visibility         = "VISIBLE"
                tooltip_visibility = "HIDDEN"
                type               = "LINE"
              }
            }
          }
          column_hierarchies {
            date_time_hierarchy {
              hierarchy_id = "ov-kpi-failed.trend"
            }
          }
        }
      }

      visuals {
        kpi_visual {
          visual_id = "ov-kpi-principals"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Unique Principals</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              trend_groups {
                date_dimension_field {
                  field_id = "ov-kpi-principals.trend"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "event_ts"
                  }
                  date_granularity = "DAY"
                  hierarchy_id     = "ov-kpi-principals.trend"
                }
              }
              values {
                categorical_measure_field {
                  field_id = "ov-kpi-principals.value"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "principal_arn"
                  }
                  aggregation_function = "DISTINCT_COUNT"
                }
              }
            }
            kpi_options {
              primary_value_display_type = "ACTUAL"
              sparkline {
                visibility         = "VISIBLE"
                tooltip_visibility = "HIDDEN"
                type               = "LINE"
              }
            }
          }
          column_hierarchies {
            date_time_hierarchy {
              hierarchy_id = "ov-kpi-principals.trend"
            }
          }
        }
      }

      visuals {
        kpi_visual {
          visual_id = "ov-kpi-customers"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Active Customers</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              trend_groups {
                date_dimension_field {
                  field_id = "ov-kpi-customers.trend"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "event_ts"
                  }
                  date_granularity = "DAY"
                  hierarchy_id     = "ov-kpi-customers.trend"
                }
              }
              values {
                categorical_measure_field {
                  field_id = "ov-kpi-customers.value"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "customer"
                  }
                  aggregation_function = "DISTINCT_COUNT"
                }
              }
            }
            kpi_options {
              primary_value_display_type = "ACTUAL"
              sparkline {
                visibility         = "VISIBLE"
                tooltip_visibility = "HIDDEN"
                type               = "LINE"
              }
            }
          }
          column_hierarchies {
            date_time_hierarchy {
              hierarchy_id = "ov-kpi-customers.trend"
            }
          }
        }
      }

      visuals {
        kpi_visual {
          visual_id = "ov-kpi-ips"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Unique Source IPs</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              trend_groups {
                date_dimension_field {
                  field_id = "ov-kpi-ips.trend"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "event_ts"
                  }
                  date_granularity = "DAY"
                  hierarchy_id     = "ov-kpi-ips.trend"
                }
              }
              values {
                categorical_measure_field {
                  field_id = "ov-kpi-ips.value"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "source_ip"
                  }
                  aggregation_function = "DISTINCT_COUNT"
                }
              }
            }
            kpi_options {
              primary_value_display_type = "ACTUAL"
              sparkline {
                visibility         = "VISIBLE"
                tooltip_visibility = "HIDDEN"
                type               = "LINE"
              }
            }
          }
          column_hierarchies {
            date_time_hierarchy {
              hierarchy_id = "ov-kpi-ips.trend"
            }
          }
        }
      }

      visuals {
        line_chart_visual {
          visual_id = "ov-line-volume"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Event Volume Over Time</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              line_chart_aggregated_field_wells {
                category {
                  date_dimension_field {
                    field_id = "ov-line-volume.date"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    hierarchy_id = "ov-line-volume.date"
                  }
                }
                values {
                  date_measure_field {
                    field_id = "ov-line-volume.count"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              category_sort {
                field_sort {
                  field_id  = "ov-line-volume.date"
                  direction = "ASC"
                }
              }
              category_items_limit_configuration {
                other_categories = "INCLUDE"
              }
              color_items_limit_configuration {
                other_categories = "INCLUDE"
              }
              small_multiples_limit_configuration {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
            }
            type = "LINE"
          }
          column_hierarchies {
            date_time_hierarchy {
              hierarchy_id = "ov-line-volume.date"
            }
          }
        }
      }

      visuals {
        bar_chart_visual {
          visual_id = "ov-bar-topapi"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Top API Calls</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              bar_chart_aggregated_field_wells {
                category {
                  categorical_dimension_field {
                    field_id = "ov-bar-topapi.eventname"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "eventname"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "ov-bar-topapi.count"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              category_sort {
                field_sort {
                  field_id  = "ov-bar-topapi.count"
                  direction = "DESC"
                }
              }
              category_items_limit {
                items_limit      = 15
                other_categories = "INCLUDE"
              }
              color_items_limit {
                other_categories = "INCLUDE"
              }
              small_multiples_limit_configuration {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
            }
            orientation = "HORIZONTAL"
          }
        }
      }

      visuals {
        pie_chart_visual {
          visual_id = "ov-donut-service"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Activity by AWS Service</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              pie_chart_aggregated_field_wells {
                category {
                  categorical_dimension_field {
                    field_id = "ov-donut-service.eventsource"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "eventsource"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "ov-donut-service.count"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              category_sort {
                field_sort {
                  field_id  = "ov-donut-service.count"
                  direction = "DESC"
                }
              }
              category_items_limit {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
              small_multiples_limit_configuration {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
            }
            donut_options {
              arc_options {
                arc_thickness = "MEDIUM"
              }
            }
            legend {
              visibility = "VISIBLE"
            }
          }
        }
      }

      visuals {
        pie_chart_visual {
          visual_id = "ov-donut-readwrite"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Read vs Write</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              pie_chart_aggregated_field_wells {
                category {
                  categorical_dimension_field {
                    field_id = "ov-donut-readwrite.readonly"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "readonly"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "ov-donut-readwrite.count"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              category_items_limit {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
              small_multiples_limit_configuration {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
            }
            donut_options {
              arc_options {
                arc_thickness = "MEDIUM"
              }
            }
            legend {
              visibility = "VISIBLE"
            }
          }
        }
      }

      visuals {
        pie_chart_visual {
          visual_id = "ov-pie-region"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Activity by Region</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              pie_chart_aggregated_field_wells {
                category {
                  categorical_dimension_field {
                    field_id = "ov-pie-region.awsregion"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "awsregion"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "ov-pie-region.count"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              category_sort {
                field_sort {
                  field_id  = "ov-pie-region.count"
                  direction = "DESC"
                }
              }
              category_items_limit {
                items_limit      = 12
                other_categories = "INCLUDE"
              }
              small_multiples_limit_configuration {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
            }
            # KNOWN RESIDUAL DIFF: QuickSight stores this full pie as
            # donut_options { arc_options { arc_thickness = "WHOLE" } }, but the
            # AWS provider (≤5.100.0) only validates SMALL/MEDIUM/LARGE, so WHOLE
            # cannot be written here. Plan therefore always shows a harmless
            # in-place "remove donut_options" on this visual; the server ignores
            # it and re-stores WHOLE. Add the block back if the provider ever
            # accepts WHOLE.
            legend {
              visibility = "VISIBLE"
            }
          }
        }
      }

      layouts {
        configuration {
          grid_layout {
            elements {
              element_id   = "ov-kpi-total"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 7
              row_index    = 0
              row_span     = 4
            }
            elements {
              element_id   = "ov-kpi-failed"
              element_type = "VISUAL"
              column_index = 7
              column_span  = 7
              row_index    = 0
              row_span     = 4
            }
            elements {
              element_id   = "ov-kpi-principals"
              element_type = "VISUAL"
              column_index = 14
              column_span  = 7
              row_index    = 0
              row_span     = 4
            }
            elements {
              element_id   = "ov-kpi-customers"
              element_type = "VISUAL"
              column_index = 21
              column_span  = 7
              row_index    = 0
              row_span     = 4
            }
            elements {
              element_id   = "ov-kpi-ips"
              element_type = "VISUAL"
              column_index = 28
              column_span  = 8
              row_index    = 0
              row_span     = 4
            }
            elements {
              element_id   = "ov-line-volume"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 24
              row_index    = 4
              row_span     = 8
            }
            elements {
              element_id   = "ov-bar-topapi"
              element_type = "VISUAL"
              column_index = 24
              column_span  = 12
              row_index    = 4
              row_span     = 8
            }
            elements {
              element_id   = "ov-donut-service"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 12
              row_index    = 12
              row_span     = 8
            }
            elements {
              element_id   = "ov-donut-readwrite"
              element_type = "VISUAL"
              column_index = 12
              column_span  = 12
              row_index    = 12
              row_span     = 8
            }
            elements {
              element_id   = "ov-pie-region"
              element_type = "VISUAL"
              column_index = 24
              column_span  = 12
              row_index    = 12
              row_span     = 8
            }
            canvas_size_options {
              screen_canvas_size_options {
                resize_option             = "FIXED"
                optimized_view_port_width = "1600px"
              }
            }
          }
        }
      }
      content_type = "INTERACTIVE"
    }

    # ════════════════════════════════════════════════════════════════════════
    # SHEET 2 — SECURITY & THREAT HUNTING
    # ════════════════════════════════════════════════════════════════════════
    sheets {
      sheet_id = "security"
      name     = "Security"

      filter_controls {
        date_time_picker {
          filter_control_id = "ctl-sec-daterange"
          source_filter_id  = "f-sec-daterange"
          title             = "Date range"
          type              = "DATE_RANGE"
          display_options {
            date_time_format = "YYYY-MM-DD"
            title_options {
              visibility = "VISIBLE"
              font_configuration {}
            }
          }
        }
      }

      visuals {
        kpi_visual {
          visual_id = "sec-kpi-failed"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Failed / Denied Events</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              trend_groups {
                date_dimension_field {
                  field_id = "sec-kpi-failed.trend"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "event_ts"
                  }
                  date_granularity = "DAY"
                  hierarchy_id     = "sec-kpi-failed.trend"
                }
              }
              values {
                numerical_measure_field {
                  field_id = "sec-kpi-failed.value"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "is_error"
                  }
                  aggregation_function {
                    simple_numerical_aggregation = "SUM"
                  }
                }
              }
            }
            kpi_options {
              primary_value_display_type = "ACTUAL"
              sparkline {
                visibility         = "VISIBLE"
                tooltip_visibility = "HIDDEN"
                type               = "LINE"
              }
            }
          }
          column_hierarchies {
            date_time_hierarchy {
              hierarchy_id = "sec-kpi-failed.trend"
            }
          }
        }
      }

      visuals {
        line_chart_visual {
          visual_id = "sec-line-fail"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Failures / Denials Over Time</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              line_chart_aggregated_field_wells {
                category {
                  date_dimension_field {
                    field_id = "sec-line-fail.date"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    hierarchy_id = "sec-line-fail.date"
                  }
                }
                values {
                  numerical_measure_field {
                    field_id = "sec-line-fail.failures"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "is_error"
                    }
                    aggregation_function {
                      simple_numerical_aggregation = "SUM"
                    }
                  }
                }
              }
            }
            sort_configuration {
              category_sort {
                field_sort {
                  field_id  = "sec-line-fail.date"
                  direction = "ASC"
                }
              }
              category_items_limit_configuration {
                other_categories = "INCLUDE"
              }
              color_items_limit_configuration {
                other_categories = "INCLUDE"
              }
              small_multiples_limit_configuration {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
            }
            type = "LINE"
          }
          column_hierarchies {
            date_time_hierarchy {
              hierarchy_id = "sec-line-fail.date"
            }
          }
        }
      }

      visuals {
        bar_chart_visual {
          visual_id = "sec-bar-errorcodes"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Top Error Codes</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              bar_chart_aggregated_field_wells {
                category {
                  categorical_dimension_field {
                    field_id = "sec-bar-errorcodes.errorcode"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "errorcode"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "sec-bar-errorcodes.count"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              category_sort {
                field_sort {
                  field_id  = "sec-bar-errorcodes.count"
                  direction = "DESC"
                }
              }
              category_items_limit {
                items_limit      = 15
                other_categories = "INCLUDE"
              }
              color_items_limit {
                other_categories = "INCLUDE"
              }
              small_multiples_limit_configuration {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
            }
            orientation = "HORIZONTAL"
          }
        }
      }

      visuals {
        bar_chart_visual {
          visual_id = "sec-bar-denied-principals"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Top Principals by Failures</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              bar_chart_aggregated_field_wells {
                category {
                  categorical_dimension_field {
                    field_id = "sec-bar-denied-principals.principal"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "principal_name"
                    }
                  }
                }
                values {
                  numerical_measure_field {
                    field_id = "sec-bar-denied-principals.failures"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "is_error"
                    }
                    aggregation_function {
                      simple_numerical_aggregation = "SUM"
                    }
                  }
                }
              }
            }
            sort_configuration {
              category_sort {
                field_sort {
                  field_id  = "sec-bar-denied-principals.failures"
                  direction = "DESC"
                }
              }
              category_items_limit {
                items_limit      = 15
                other_categories = "INCLUDE"
              }
              color_items_limit {
                other_categories = "INCLUDE"
              }
              small_multiples_limit_configuration {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
            }
            orientation = "HORIZONTAL"
          }
        }
      }

      visuals {
        pie_chart_visual {
          visual_id = "sec-donut-mfa"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>MFA Coverage</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              pie_chart_aggregated_field_wells {
                category {
                  categorical_dimension_field {
                    field_id = "sec-donut-mfa.status"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "mfa_status"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "sec-donut-mfa.count"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              category_items_limit {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
              small_multiples_limit_configuration {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
            }
            donut_options {
              arc_options {
                arc_thickness = "MEDIUM"
              }
            }
            legend {
              visibility = "VISIBLE"
            }
          }
        }
      }

      visuals {
        table_visual {
          visual_id = "sec-tbl-console"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Console Logins (watch No-MFA)</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              table_aggregated_field_wells {
                group_by {
                  date_dimension_field {
                    field_id = "sec-tbl-console.event_ts"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "sec-tbl-console.principal"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "principal_name"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "sec-tbl-console.source_ip"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "source_ip"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "sec-tbl-console.mfa"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "mfa_used"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "sec-tbl-console.errorcode"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "errorcode"
                    }
                  }
                }
              }
            }
            sort_configuration {
              row_sort {
                field_sort {
                  field_id  = "sec-tbl-console.event_ts"
                  direction = "DESC"
                }
              }
            }
          }
        }
      }

      visuals {
        table_visual {
          visual_id = "sec-tbl-root"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Root Account Activity</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              table_aggregated_field_wells {
                group_by {
                  date_dimension_field {
                    field_id = "sec-tbl-root.event_ts"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "sec-tbl-root.eventname"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "eventname"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "sec-tbl-root.source_ip"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "source_ip"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "sec-tbl-root.awsregion"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "awsregion"
                    }
                  }
                }
              }
            }
            sort_configuration {
              row_sort {
                field_sort {
                  field_id  = "sec-tbl-root.event_ts"
                  direction = "DESC"
                }
              }
            }
          }
        }
      }

      visuals {
        table_visual {
          visual_id = "sec-tbl-iam-kms"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>IAM &amp; KMS Admin Changes</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              table_aggregated_field_wells {
                group_by {
                  date_dimension_field {
                    field_id = "sec-tbl-iam-kms.event_ts"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "sec-tbl-iam-kms.principal"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "principal_name"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "sec-tbl-iam-kms.eventname"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "eventname"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "sec-tbl-iam-kms.errorcode"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "errorcode"
                    }
                  }
                }
              }
            }
            sort_configuration {
              row_sort {
                field_sort {
                  field_id  = "sec-tbl-iam-kms.event_ts"
                  direction = "DESC"
                }
              }
            }
          }
        }
      }

      visuals {
        table_visual {
          visual_id = "sec-tbl-agents"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Activity by User Agent</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              table_aggregated_field_wells {
                group_by {
                  categorical_dimension_field {
                    field_id = "sec-tbl-agents.useragent"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "useragent"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "sec-tbl-agents.principal"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "principal_name"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "sec-tbl-agents.count"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              row_sort {
                field_sort {
                  field_id  = "sec-tbl-agents.count"
                  direction = "DESC"
                }
              }
            }
          }
        }
      }

      visuals {
        heat_map_visual {
          visual_id = "sec-heat-hour"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Activity by Principal &amp; Hour (UTC)</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              heat_map_aggregated_field_wells {
                rows {
                  categorical_dimension_field {
                    field_id = "sec-heat-hour.principal"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "principal_name"
                    }
                  }
                }
                columns {
                  categorical_dimension_field {
                    field_id = "sec-heat-hour.hour"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_hour"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "sec-heat-hour.count"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              heat_map_row_sort {
                field_sort {
                  field_id  = "sec-heat-hour.count"
                  direction = "DESC"
                }
              }
              # QuickSight refuses to persist a column sort on the hour dimension —
              # it canonicalizes to count DESC on read-back, so config matches that
              # to stay zero-diff.
              heat_map_column_sort {
                field_sort {
                  field_id  = "sec-heat-hour.count"
                  direction = "DESC"
                }
              }
              heat_map_row_items_limit_configuration {
                items_limit      = 20
                other_categories = "EXCLUDE"
              }
              heat_map_column_items_limit_configuration {
                items_limit      = 24
                other_categories = "EXCLUDE"
              }
            }
            color_scale {
              color_fill_type = "GRADIENT"
              colors {
                color = "#F2F6FB"
              }
              colors {
                color = "#1F6FB2"
              }
            }
            legend {
              visibility = "VISIBLE"
            }
          }
        }
      }

      layouts {
        configuration {
          grid_layout {
            elements {
              element_id   = "sec-kpi-failed"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 8
              row_index    = 0
              row_span     = 8
            }
            elements {
              element_id   = "sec-line-fail"
              element_type = "VISUAL"
              column_index = 8
              column_span  = 28
              row_index    = 0
              row_span     = 8
            }
            elements {
              element_id   = "sec-bar-errorcodes"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 12
              row_index    = 8
              row_span     = 8
            }
            elements {
              element_id   = "sec-bar-denied-principals"
              element_type = "VISUAL"
              column_index = 12
              column_span  = 12
              row_index    = 8
              row_span     = 8
            }
            elements {
              element_id   = "sec-donut-mfa"
              element_type = "VISUAL"
              column_index = 24
              column_span  = 12
              row_index    = 8
              row_span     = 8
            }
            elements {
              element_id   = "sec-tbl-console"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 18
              row_index    = 16
              row_span     = 8
            }
            elements {
              element_id   = "sec-tbl-root"
              element_type = "VISUAL"
              column_index = 18
              column_span  = 18
              row_index    = 16
              row_span     = 8
            }
            elements {
              element_id   = "sec-tbl-iam-kms"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 18
              row_index    = 24
              row_span     = 8
            }
            elements {
              element_id   = "sec-tbl-agents"
              element_type = "VISUAL"
              column_index = 18
              column_span  = 18
              row_index    = 24
              row_span     = 8
            }
            elements {
              element_id   = "sec-heat-hour"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 36
              row_index    = 32
              row_span     = 10
            }
            canvas_size_options {
              screen_canvas_size_options {
                resize_option             = "FIXED"
                optimized_view_port_width = "1600px"
              }
            }
          }
        }
      }
      content_type = "INTERACTIVE"
    }

    # ════════════════════════════════════════════════════════════════════════
    # SHEET 3 — PHI DATA ACCESS  (sheet-wide filter restricts to S3 object events)
    # ════════════════════════════════════════════════════════════════════════
    sheets {
      sheet_id = "phi"
      name     = "PHI Data Access"

      filter_controls {
        date_time_picker {
          filter_control_id = "ctl-phi-daterange"
          source_filter_id  = "f-phi-daterange"
          title             = "Date range"
          type              = "DATE_RANGE"
          display_options {
            date_time_format = "YYYY-MM-DD"
            title_options {
              visibility = "VISIBLE"
              font_configuration {}
            }
          }
        }
      }

      visuals {
        kpi_visual {
          visual_id = "phi-kpi-total"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>PHI Object Events</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              trend_groups {
                date_dimension_field {
                  field_id = "phi-kpi-total.trend"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "event_ts"
                  }
                  date_granularity = "DAY"
                  hierarchy_id     = "phi-kpi-total.trend"
                }
              }
              values {
                date_measure_field {
                  field_id = "phi-kpi-total.value"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "event_ts"
                  }
                  aggregation_function = "COUNT"
                }
              }
            }
            kpi_options {
              primary_value_display_type = "ACTUAL"
              sparkline {
                visibility         = "VISIBLE"
                tooltip_visibility = "HIDDEN"
                type               = "LINE"
              }
            }
          }
          column_hierarchies {
            date_time_hierarchy {
              hierarchy_id = "phi-kpi-total.trend"
            }
          }
        }
      }

      visuals {
        kpi_visual {
          visual_id = "phi-kpi-read"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Objects Read</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              trend_groups {
                date_dimension_field {
                  field_id = "phi-kpi-read.trend"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "event_ts"
                  }
                  date_granularity = "DAY"
                  hierarchy_id     = "phi-kpi-read.trend"
                }
              }
              values {
                date_measure_field {
                  field_id = "phi-kpi-read.value"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "event_ts"
                  }
                  aggregation_function = "COUNT"
                }
              }
            }
            kpi_options {
              primary_value_display_type = "ACTUAL"
              sparkline {
                visibility         = "VISIBLE"
                tooltip_visibility = "HIDDEN"
                type               = "LINE"
              }
            }
          }
          column_hierarchies {
            date_time_hierarchy {
              hierarchy_id = "phi-kpi-read.trend"
            }
          }
        }
      }

      visuals {
        kpi_visual {
          visual_id = "phi-kpi-write"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Objects Written</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              trend_groups {
                date_dimension_field {
                  field_id = "phi-kpi-write.trend"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "event_ts"
                  }
                  date_granularity = "DAY"
                  hierarchy_id     = "phi-kpi-write.trend"
                }
              }
              values {
                date_measure_field {
                  field_id = "phi-kpi-write.value"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "event_ts"
                  }
                  aggregation_function = "COUNT"
                }
              }
            }
            kpi_options {
              primary_value_display_type = "ACTUAL"
              sparkline {
                visibility         = "VISIBLE"
                tooltip_visibility = "HIDDEN"
                type               = "LINE"
              }
            }
          }
          column_hierarchies {
            date_time_hierarchy {
              hierarchy_id = "phi-kpi-write.trend"
            }
          }
        }
      }

      visuals {
        kpi_visual {
          visual_id = "phi-kpi-delete"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Objects Deleted</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              trend_groups {
                date_dimension_field {
                  field_id = "phi-kpi-delete.trend"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "event_ts"
                  }
                  date_granularity = "DAY"
                  hierarchy_id     = "phi-kpi-delete.trend"
                }
              }
              values {
                date_measure_field {
                  field_id = "phi-kpi-delete.value"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "event_ts"
                  }
                  aggregation_function = "COUNT"
                }
              }
            }
            kpi_options {
              primary_value_display_type = "ACTUAL"
              sparkline {
                visibility         = "VISIBLE"
                tooltip_visibility = "HIDDEN"
                type               = "LINE"
              }
            }
          }
          column_hierarchies {
            date_time_hierarchy {
              hierarchy_id = "phi-kpi-delete.trend"
            }
          }
        }
      }

      visuals {
        line_chart_visual {
          visual_id = "phi-line-access"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>PHI Data Access Over Time (by operation)</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              line_chart_aggregated_field_wells {
                category {
                  date_dimension_field {
                    field_id = "phi-line-access.date"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    hierarchy_id = "phi-line-access.date"
                  }
                }
                colors {
                  categorical_dimension_field {
                    field_id = "phi-line-access.eventname"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "eventname"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "phi-line-access.count"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              category_sort {
                field_sort {
                  field_id  = "phi-line-access.date"
                  direction = "ASC"
                }
              }
              category_items_limit_configuration {
                other_categories = "INCLUDE"
              }
              color_items_limit_configuration {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
              small_multiples_limit_configuration {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
            }
            type = "LINE"
          }
          column_hierarchies {
            date_time_hierarchy {
              hierarchy_id = "phi-line-access.date"
            }
          }
        }
      }

      visuals {
        bar_chart_visual {
          visual_id = "phi-bar-bucket"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Access by Bucket</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              bar_chart_aggregated_field_wells {
                category {
                  categorical_dimension_field {
                    field_id = "phi-bar-bucket.bucket"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "s3_bucket"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "phi-bar-bucket.count"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              category_sort {
                field_sort {
                  field_id  = "phi-bar-bucket.count"
                  direction = "DESC"
                }
              }
              category_items_limit {
                items_limit      = 20
                other_categories = "INCLUDE"
              }
              color_items_limit {
                other_categories = "INCLUDE"
              }
              small_multiples_limit_configuration {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
            }
            orientation = "HORIZONTAL"
          }
        }
      }

      visuals {
        bar_chart_visual {
          visual_id = "phi-bar-principal"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Access by Principal</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              bar_chart_aggregated_field_wells {
                category {
                  categorical_dimension_field {
                    field_id = "phi-bar-principal.principal"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "principal_name"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "phi-bar-principal.count"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              category_sort {
                field_sort {
                  field_id  = "phi-bar-principal.count"
                  direction = "DESC"
                }
              }
              category_items_limit {
                items_limit      = 20
                other_categories = "INCLUDE"
              }
              color_items_limit {
                other_categories = "INCLUDE"
              }
              small_multiples_limit_configuration {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
            }
            orientation = "HORIZONTAL"
          }
        }
      }

      visuals {
        table_visual {
          visual_id = "phi-tbl-detail"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Who Accessed What (audit log)</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              table_aggregated_field_wells {
                group_by {
                  date_dimension_field {
                    field_id = "phi-tbl-detail.event_ts"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "phi-tbl-detail.principal"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "principal_name"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "phi-tbl-detail.eventname"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "eventname"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "phi-tbl-detail.bucket"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "s3_bucket"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "phi-tbl-detail.customer"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "customer"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "phi-tbl-detail.source_ip"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "source_ip"
                    }
                  }
                }
              }
            }
            sort_configuration {
              row_sort {
                field_sort {
                  field_id  = "phi-tbl-detail.event_ts"
                  direction = "DESC"
                }
              }
            }
            table_options {
              cell_style {
                height = 30
              }
            }
          }
        }
      }

      visuals {
        table_visual {
          visual_id = "phi-tbl-deletes"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Object Deletions (sensitive)</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              table_aggregated_field_wells {
                group_by {
                  date_dimension_field {
                    field_id = "phi-tbl-deletes.event_ts"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "phi-tbl-deletes.principal"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "principal_name"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "phi-tbl-deletes.bucket"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "s3_bucket"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "phi-tbl-deletes.customer"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "customer"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "phi-tbl-deletes.mfa"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "mfa_used"
                    }
                  }
                }
              }
            }
            sort_configuration {
              row_sort {
                field_sort {
                  field_id  = "phi-tbl-deletes.event_ts"
                  direction = "DESC"
                }
              }
            }
          }
        }
      }

      layouts {
        configuration {
          grid_layout {
            elements {
              element_id   = "phi-kpi-total"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 9
              row_index    = 0
              row_span     = 4
            }
            elements {
              element_id   = "phi-kpi-read"
              element_type = "VISUAL"
              column_index = 9
              column_span  = 9
              row_index    = 0
              row_span     = 4
            }
            elements {
              element_id   = "phi-kpi-write"
              element_type = "VISUAL"
              column_index = 18
              column_span  = 9
              row_index    = 0
              row_span     = 4
            }
            elements {
              element_id   = "phi-kpi-delete"
              element_type = "VISUAL"
              column_index = 27
              column_span  = 9
              row_index    = 0
              row_span     = 4
            }
            elements {
              element_id   = "phi-line-access"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 36
              row_index    = 4
              row_span     = 8
            }
            elements {
              element_id   = "phi-bar-bucket"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 18
              row_index    = 12
              row_span     = 8
            }
            elements {
              element_id   = "phi-bar-principal"
              element_type = "VISUAL"
              column_index = 18
              column_span  = 18
              row_index    = 12
              row_span     = 8
            }
            elements {
              element_id   = "phi-tbl-detail"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 36
              row_index    = 20
              row_span     = 10
            }
            elements {
              element_id   = "phi-tbl-deletes"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 36
              row_index    = 30
              row_span     = 8
            }
            canvas_size_options {
              screen_canvas_size_options {
                resize_option             = "FIXED"
                optimized_view_port_width = "1600px"
              }
            }
          }
        }
      }
      content_type = "INTERACTIVE"
    }

    # ════════════════════════════════════════════════════════════════════════
    # SHEET 4 — CUSTOMERS
    # ════════════════════════════════════════════════════════════════════════
    sheets {
      sheet_id = "customers"
      name     = "Customers"

      filter_controls {
        date_time_picker {
          filter_control_id = "ctl-cust-daterange"
          source_filter_id  = "f-cust-daterange"
          title             = "Date range"
          type              = "DATE_RANGE"
          display_options {
            date_time_format = "YYYY-MM-DD"
            title_options {
              visibility = "VISIBLE"
              font_configuration {}
            }
          }
        }
      }

      visuals {
        kpi_visual {
          visual_id = "cust-kpi-active"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Active Customers</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              trend_groups {
                date_dimension_field {
                  field_id = "cust-kpi-active.trend"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "event_ts"
                  }
                  date_granularity = "DAY"
                  hierarchy_id     = "cust-kpi-active.trend"
                }
              }
              values {
                categorical_measure_field {
                  field_id = "cust-kpi-active.value"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "customer"
                  }
                  aggregation_function = "DISTINCT_COUNT"
                }
              }
            }
            kpi_options {
              primary_value_display_type = "ACTUAL"
              sparkline {
                visibility         = "VISIBLE"
                tooltip_visibility = "HIDDEN"
                type               = "LINE"
              }
            }
          }
          column_hierarchies {
            date_time_hierarchy {
              hierarchy_id = "cust-kpi-active.trend"
            }
          }
        }
      }

      visuals {
        bar_chart_visual {
          visual_id = "cust-bar-activity"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Activity by Customer</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              bar_chart_aggregated_field_wells {
                category {
                  categorical_dimension_field {
                    field_id = "cust-bar-activity.customer"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "customer"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "cust-bar-activity.count"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              category_sort {
                field_sort {
                  field_id  = "cust-bar-activity.count"
                  direction = "DESC"
                }
              }
              category_items_limit {
                items_limit      = 25
                other_categories = "INCLUDE"
              }
              color_items_limit {
                other_categories = "INCLUDE"
              }
              small_multiples_limit_configuration {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
            }
            orientation = "VERTICAL"
          }
        }
      }

      visuals {
        line_chart_visual {
          visual_id = "cust-line-trend"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Customer Activity Over Time</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              line_chart_aggregated_field_wells {
                category {
                  date_dimension_field {
                    field_id = "cust-line-trend.date"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    hierarchy_id = "cust-line-trend.date"
                  }
                }
                colors {
                  categorical_dimension_field {
                    field_id = "cust-line-trend.customer"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "customer"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "cust-line-trend.count"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              category_sort {
                field_sort {
                  field_id  = "cust-line-trend.date"
                  direction = "ASC"
                }
              }
              category_items_limit_configuration {
                other_categories = "INCLUDE"
              }
              color_items_limit_configuration {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
              small_multiples_limit_configuration {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
            }
            type = "LINE"
          }
          column_hierarchies {
            date_time_hierarchy {
              hierarchy_id = "cust-line-trend.date"
            }
          }
        }
      }

      visuals {
        table_visual {
          visual_id = "cust-tbl-detail"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Customer Data Access Detail</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              table_aggregated_field_wells {
                group_by {
                  categorical_dimension_field {
                    field_id = "cust-tbl-detail.customer"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "customer"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "cust-tbl-detail.bucket"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "s3_bucket"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "cust-tbl-detail.eventname"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "eventname"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "cust-tbl-detail.count"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              row_sort {
                field_sort {
                  field_id  = "cust-tbl-detail.count"
                  direction = "DESC"
                }
              }
            }
          }
        }
      }

      visuals {
        table_visual {
          visual_id = "cust-tbl-errors"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Customer Error Summary</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              table_aggregated_field_wells {
                group_by {
                  categorical_dimension_field {
                    field_id = "cust-tbl-errors.customer"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "customer"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "cust-tbl-errors.total"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
                values {
                  numerical_measure_field {
                    field_id = "cust-tbl-errors.failures"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "is_error"
                    }
                    aggregation_function {
                      simple_numerical_aggregation = "SUM"
                    }
                  }
                }
              }
            }
            sort_configuration {
              row_sort {
                field_sort {
                  field_id  = "cust-tbl-errors.failures"
                  direction = "DESC"
                }
              }
            }
          }
        }
      }

      visuals {
        bar_chart_visual {
          visual_id = "cust-bar-datavol"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Top Customers by Data Access</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              bar_chart_aggregated_field_wells {
                category {
                  categorical_dimension_field {
                    field_id = "cust-bar-datavol.customer"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "customer"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "cust-bar-datavol.count"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              category_sort {
                field_sort {
                  field_id  = "cust-bar-datavol.count"
                  direction = "DESC"
                }
              }
              category_items_limit {
                items_limit      = 20
                other_categories = "INCLUDE"
              }
              color_items_limit {
                other_categories = "INCLUDE"
              }
              small_multiples_limit_configuration {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
            }
            orientation = "HORIZONTAL"
          }
        }
      }

      layouts {
        configuration {
          grid_layout {
            elements {
              element_id   = "cust-kpi-active"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 8
              row_index    = 0
              row_span     = 8
            }
            elements {
              element_id   = "cust-bar-activity"
              element_type = "VISUAL"
              column_index = 8
              column_span  = 28
              row_index    = 0
              row_span     = 8
            }
            elements {
              element_id   = "cust-line-trend"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 36
              row_index    = 8
              row_span     = 8
            }
            elements {
              element_id   = "cust-tbl-detail"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 18
              row_index    = 16
              row_span     = 10
            }
            elements {
              element_id   = "cust-tbl-errors"
              element_type = "VISUAL"
              column_index = 18
              column_span  = 18
              row_index    = 16
              row_span     = 10
            }
            elements {
              element_id   = "cust-bar-datavol"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 36
              row_index    = 26
              row_span     = 8
            }
            canvas_size_options {
              screen_canvas_size_options {
                resize_option             = "FIXED"
                optimized_view_port_width = "1600px"
              }
            }
          }
        }
      }
      content_type = "INTERACTIVE"
    }

    # ════════════════════════════════════════════════════════════════════════
    # SHEET 5 — SOURCE IP ACCESS  (IP × time of S3 activity, per scoped credential)
    #   Customer block: is_customer_cred=1 AND has_s3_bucket=1 AND eventsource=s3
    #                   (fg-ip-customer-cred / -hasbucket / -s3 — separate groups so they AND)
    #   Vendor block:   is_vendor_cred=1   AND has_s3_bucket=1 AND eventsource=s3
    #                   (fg-ip-vendor-cred / -hasbucket / -s3)
    # ════════════════════════════════════════════════════════════════════════
    sheets {
      sheet_id = "ipaccess"
      name     = "Source IP Access"

      filter_controls {
        date_time_picker {
          filter_control_id = "ctl-ip-daterange"
          source_filter_id  = "f-ip-daterange"
          title             = "Date range"
          type              = "DATE_RANGE"
          display_options {
            date_time_format = "YYYY-MM-DD"
            title_options {
              visibility = "VISIBLE"
              font_configuration {}
            }
          }
        }
      }

      # ── Customer block ──────────────────────────────────────────────────────
      visuals {
        kpi_visual {
          visual_id = "ip-cust-kpi-ips"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Unique Source IPs — Customers</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              trend_groups {
                date_dimension_field {
                  field_id = "ip-cust-kpi-ips.trend"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "event_ts"
                  }
                  date_granularity = "DAY"
                  hierarchy_id     = "ip-cust-kpi-ips.trend"
                }
              }
              values {
                categorical_measure_field {
                  field_id = "ip-cust-kpi-ips.value"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "source_ip"
                  }
                  aggregation_function = "DISTINCT_COUNT"
                }
              }
            }
            kpi_options {
              primary_value_display_type = "ACTUAL"
              sparkline {
                visibility         = "VISIBLE"
                tooltip_visibility = "HIDDEN"
                type               = "LINE"
              }
            }
          }
          column_hierarchies {
            date_time_hierarchy {
              hierarchy_id = "ip-cust-kpi-ips.trend"
            }
          }
        }
      }

      visuals {
        bar_chart_visual {
          visual_id = "ip-cust-bar-ip"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Top Source IPs — Customers</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              bar_chart_aggregated_field_wells {
                category {
                  categorical_dimension_field {
                    field_id = "ip-cust-bar-ip.source_ip"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "source_ip"
                    }
                  }
                }
                # Colors each IP's bar by its GeoLite2 country, so origin is visible
                # at a glance without opening the table/geo-map visuals.
                colors {
                  categorical_dimension_field {
                    field_id = "ip-cust-bar-ip.geo_country"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "geo_country"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "ip-cust-bar-ip.count"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              category_sort {
                field_sort {
                  field_id  = "ip-cust-bar-ip.count"
                  direction = "DESC"
                }
              }
              category_items_limit {
                items_limit      = 20
                other_categories = "INCLUDE"
              }
              # ColorItemsLimit itself must be 1-100 (QuickSight-enforced cap, separate
              # from the category x color <=10000 product rule); 100 is the max allowed.
              color_items_limit {
                items_limit      = 100
                other_categories = "INCLUDE"
              }
              small_multiples_limit_configuration {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
            }
            orientation      = "HORIZONTAL"
            bars_arrangement = "STACKED"
            tooltip {
              selected_tooltip_type = "DETAILED"
              tooltip_visibility    = "VISIBLE"
              field_base_tooltip {
                aggregation_visibility = "HIDDEN"
                tooltip_title_type     = "PRIMARY_VALUE"
                tooltip_fields {
                  field_tooltip_item {
                    field_id   = "ip-cust-bar-ip.source_ip"
                    label      = "Source IP"
                    visibility = "VISIBLE"
                  }
                }
                tooltip_fields {
                  field_tooltip_item {
                    field_id   = "ip-cust-bar-ip.count"
                    label      = "Events"
                    visibility = "VISIBLE"
                  }
                }
                tooltip_fields {
                  field_tooltip_item {
                    field_id   = "ip-cust-bar-ip.geo_country"
                    label      = "Country"
                    visibility = "VISIBLE"
                  }
                }
                tooltip_fields {
                  column_tooltip_item {
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "geo_city"
                    }
                    label      = "City"
                    visibility = "VISIBLE"
                  }
                }
                tooltip_fields {
                  column_tooltip_item {
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "geo_state"
                    }
                    label      = "State"
                    visibility = "VISIBLE"
                  }
                }
              }
            }
          }
        }
      }

      visuals {
        heat_map_visual {
          visual_id = "ip-cust-heat-hour"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Source IP &amp; Hour (UTC) — Customers</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              heat_map_aggregated_field_wells {
                rows {
                  categorical_dimension_field {
                    field_id = "ip-cust-heat-hour.source_ip"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "source_ip"
                    }
                  }
                }
                columns {
                  categorical_dimension_field {
                    field_id = "ip-cust-heat-hour.hour"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_hour"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "ip-cust-heat-hour.count"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              heat_map_row_sort {
                field_sort {
                  field_id  = "ip-cust-heat-hour.count"
                  direction = "DESC"
                }
              }
              # Mirrors sec-heat-hour: QuickSight canonicalizes the hour column sort to
              # count DESC on read-back, so config matches that to stay zero-diff.
              heat_map_column_sort {
                field_sort {
                  field_id  = "ip-cust-heat-hour.count"
                  direction = "DESC"
                }
              }
              heat_map_row_items_limit_configuration {
                items_limit      = 20
                other_categories = "EXCLUDE"
              }
              heat_map_column_items_limit_configuration {
                items_limit      = 24
                other_categories = "EXCLUDE"
              }
            }
            color_scale {
              color_fill_type = "GRADIENT"
              colors {
                color = "#F2F6FB"
              }
              colors {
                color = "#1F6FB2"
              }
            }
            legend {
              visibility = "VISIBLE"
            }
            # Geo enrichment stays tooltip-only here — row/column shape (IP × hour)
            # is unchanged; country/city are just added context on hover.
            tooltip {
              selected_tooltip_type = "DETAILED"
              tooltip_visibility    = "VISIBLE"
              field_base_tooltip {
                aggregation_visibility = "HIDDEN"
                tooltip_title_type     = "PRIMARY_VALUE"
                tooltip_fields {
                  field_tooltip_item {
                    field_id   = "ip-cust-heat-hour.source_ip"
                    label      = "Source IP"
                    visibility = "VISIBLE"
                  }
                }
                tooltip_fields {
                  field_tooltip_item {
                    field_id   = "ip-cust-heat-hour.hour"
                    label      = "Hour (UTC)"
                    visibility = "VISIBLE"
                  }
                }
                tooltip_fields {
                  field_tooltip_item {
                    field_id   = "ip-cust-heat-hour.count"
                    label      = "Events"
                    visibility = "VISIBLE"
                  }
                }
                tooltip_fields {
                  column_tooltip_item {
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "geo_country"
                    }
                    label      = "Country"
                    visibility = "VISIBLE"
                  }
                }
                tooltip_fields {
                  column_tooltip_item {
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "geo_city"
                    }
                    label      = "City"
                    visibility = "VISIBLE"
                  }
                }
                tooltip_fields {
                  column_tooltip_item {
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "geo_state"
                    }
                    label      = "State"
                    visibility = "VISIBLE"
                  }
                }
              }
            }
          }
        }
      }

      visuals {
        table_visual {
          visual_id = "ip-cust-tbl-detail"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Customer Bucket Access — Who / Where / When</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              table_aggregated_field_wells {
                group_by {
                  date_dimension_field {
                    field_id = "ip-cust-tbl-detail.event_ts"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "ip-cust-tbl-detail.principal"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "principal_name"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "ip-cust-tbl-detail.source_ip"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "source_ip"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "ip-cust-tbl-detail.geo_city"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "geo_city"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "ip-cust-tbl-detail.geo_state"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "geo_state"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "ip-cust-tbl-detail.geo_county"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "geo_county"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "ip-cust-tbl-detail.eventname"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "eventname"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "ip-cust-tbl-detail.bucket"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "s3_bucket"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "ip-cust-tbl-detail.customer"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "customer"
                    }
                  }
                }
              }
            }
            sort_configuration {
              row_sort {
                field_sort {
                  field_id  = "ip-cust-tbl-detail.event_ts"
                  direction = "DESC"
                }
              }
            }
            table_options {
              cell_style {
                height = 30
              }
            }
          }
        }
      }

      visuals {
        geospatial_map_visual {
          visual_id = "ip-cust-geo"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Customer Access — Geographic Origin (GeoLite2, approx)</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              geospatial_map_aggregated_field_wells {
                geospatial {
                  numerical_dimension_field {
                    field_id = "ip-cust-geo.lat"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "geo_lat"
                    }
                  }
                }
                geospatial {
                  numerical_dimension_field {
                    field_id = "ip-cust-geo.lon"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "geo_lon"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "ip-cust-geo.count"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
                # Color points by the credential identity touching that origin, so the
                # map answers "which LabCustomer-* is coming from where" at a glance
                # (legend = credential). Swap to `customer` for the cleaned researcher name.
                colors {
                  categorical_dimension_field {
                    field_id = "ip-cust-geo.principal"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "principal_name"
                    }
                  }
                }
              }
            }
            map_style_options {
              base_map_style = "LIGHT_GRAY"
            }
            # POINT (un-clustered): clustered points aggregate categories and
            # suppress the categorical color legend in reader view. Pin legend position
            # explicitly — the bare visibility=VISIBLE renders in the analysis editor but
            # not the published dashboard for points-on-map. (Reader-view geospatial legend
            # is unreliable; if this still doesn't paint, fall back to dots + tooltip.)
            point_style_options {
              selected_point_style = "POINT"
            }
            legend {
              visibility = "VISIBLE"
              position   = "BOTTOM"
              title {
                visibility = "VISIBLE"
              }
            }
            # Hover annotation: credential + event count at each origin point.
            tooltip {
              selected_tooltip_type = "DETAILED"
              tooltip_visibility    = "VISIBLE"
              field_base_tooltip {
                aggregation_visibility = "HIDDEN"
                tooltip_title_type     = "PRIMARY_VALUE"
                tooltip_fields {
                  field_tooltip_item {
                    field_id   = "ip-cust-geo.principal"
                    label      = "Credential"
                    visibility = "VISIBLE"
                  }
                }
                tooltip_fields {
                  field_tooltip_item {
                    field_id   = "ip-cust-geo.count"
                    label      = "Events"
                    visibility = "VISIBLE"
                  }
                }
              }
            }
          }
        }
      }

      # ── Vendor block ────────────────────────────────────────────────────────
      visuals {
        kpi_visual {
          visual_id = "ip-vend-kpi-ips"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Unique Source IPs — Vendors</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              trend_groups {
                date_dimension_field {
                  field_id = "ip-vend-kpi-ips.trend"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "event_ts"
                  }
                  date_granularity = "DAY"
                  hierarchy_id     = "ip-vend-kpi-ips.trend"
                }
              }
              values {
                categorical_measure_field {
                  field_id = "ip-vend-kpi-ips.value"
                  column {
                    data_set_identifier = "CloudTrail Audit Dashboard"
                    column_name         = "source_ip"
                  }
                  aggregation_function = "DISTINCT_COUNT"
                }
              }
            }
            kpi_options {
              primary_value_display_type = "ACTUAL"
              sparkline {
                visibility         = "VISIBLE"
                tooltip_visibility = "HIDDEN"
                type               = "LINE"
              }
            }
          }
          column_hierarchies {
            date_time_hierarchy {
              hierarchy_id = "ip-vend-kpi-ips.trend"
            }
          }
        }
      }

      visuals {
        bar_chart_visual {
          visual_id = "ip-vend-bar-ip"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Top Source IPs — Vendors</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              bar_chart_aggregated_field_wells {
                category {
                  categorical_dimension_field {
                    field_id = "ip-vend-bar-ip.source_ip"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "source_ip"
                    }
                  }
                }
                # Colors each IP's bar by its GeoLite2 country, so origin is visible
                # at a glance without opening the table/geo-map visuals.
                colors {
                  categorical_dimension_field {
                    field_id = "ip-vend-bar-ip.geo_country"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "geo_country"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "ip-vend-bar-ip.count"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              category_sort {
                field_sort {
                  field_id  = "ip-vend-bar-ip.count"
                  direction = "DESC"
                }
              }
              category_items_limit {
                items_limit      = 20
                other_categories = "INCLUDE"
              }
              # ColorItemsLimit itself must be 1-100 (QuickSight-enforced cap, separate
              # from the category x color <=10000 product rule); 100 is the max allowed.
              color_items_limit {
                items_limit      = 100
                other_categories = "INCLUDE"
              }
              small_multiples_limit_configuration {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
            }
            orientation      = "HORIZONTAL"
            bars_arrangement = "STACKED"
            tooltip {
              selected_tooltip_type = "DETAILED"
              tooltip_visibility    = "VISIBLE"
              field_base_tooltip {
                aggregation_visibility = "HIDDEN"
                tooltip_title_type     = "PRIMARY_VALUE"
                tooltip_fields {
                  field_tooltip_item {
                    field_id   = "ip-vend-bar-ip.source_ip"
                    label      = "Source IP"
                    visibility = "VISIBLE"
                  }
                }
                tooltip_fields {
                  field_tooltip_item {
                    field_id   = "ip-vend-bar-ip.count"
                    label      = "Events"
                    visibility = "VISIBLE"
                  }
                }
                tooltip_fields {
                  field_tooltip_item {
                    field_id   = "ip-vend-bar-ip.geo_country"
                    label      = "Country"
                    visibility = "VISIBLE"
                  }
                }
                tooltip_fields {
                  column_tooltip_item {
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "geo_city"
                    }
                    label      = "City"
                    visibility = "VISIBLE"
                  }
                }
                tooltip_fields {
                  column_tooltip_item {
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "geo_state"
                    }
                    label      = "State"
                    visibility = "VISIBLE"
                  }
                }
              }
            }
          }
        }
      }

      visuals {
        heat_map_visual {
          visual_id = "ip-vend-heat-hour"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Source IP &amp; Hour (UTC) — Vendors</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              heat_map_aggregated_field_wells {
                rows {
                  categorical_dimension_field {
                    field_id = "ip-vend-heat-hour.source_ip"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "source_ip"
                    }
                  }
                }
                columns {
                  categorical_dimension_field {
                    field_id = "ip-vend-heat-hour.hour"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_hour"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "ip-vend-heat-hour.count"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              heat_map_row_sort {
                field_sort {
                  field_id  = "ip-vend-heat-hour.count"
                  direction = "DESC"
                }
              }
              heat_map_column_sort {
                field_sort {
                  field_id  = "ip-vend-heat-hour.count"
                  direction = "DESC"
                }
              }
              heat_map_row_items_limit_configuration {
                items_limit      = 20
                other_categories = "EXCLUDE"
              }
              heat_map_column_items_limit_configuration {
                items_limit      = 24
                other_categories = "EXCLUDE"
              }
            }
            color_scale {
              color_fill_type = "GRADIENT"
              colors {
                color = "#F2F6FB"
              }
              colors {
                color = "#1F6FB2"
              }
            }
            legend {
              visibility = "VISIBLE"
            }
            # Geo enrichment stays tooltip-only here — row/column shape (IP × hour)
            # is unchanged; country/city are just added context on hover.
            tooltip {
              selected_tooltip_type = "DETAILED"
              tooltip_visibility    = "VISIBLE"
              field_base_tooltip {
                aggregation_visibility = "HIDDEN"
                tooltip_title_type     = "PRIMARY_VALUE"
                tooltip_fields {
                  field_tooltip_item {
                    field_id   = "ip-vend-heat-hour.source_ip"
                    label      = "Source IP"
                    visibility = "VISIBLE"
                  }
                }
                tooltip_fields {
                  field_tooltip_item {
                    field_id   = "ip-vend-heat-hour.hour"
                    label      = "Hour (UTC)"
                    visibility = "VISIBLE"
                  }
                }
                tooltip_fields {
                  field_tooltip_item {
                    field_id   = "ip-vend-heat-hour.count"
                    label      = "Events"
                    visibility = "VISIBLE"
                  }
                }
                tooltip_fields {
                  column_tooltip_item {
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "geo_country"
                    }
                    label      = "Country"
                    visibility = "VISIBLE"
                  }
                }
                tooltip_fields {
                  column_tooltip_item {
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "geo_city"
                    }
                    label      = "City"
                    visibility = "VISIBLE"
                  }
                }
                tooltip_fields {
                  column_tooltip_item {
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "geo_state"
                    }
                    label      = "State"
                    visibility = "VISIBLE"
                  }
                }
              }
            }
          }
        }
      }

      visuals {
        table_visual {
          visual_id = "ip-vend-tbl-detail"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Vendor Bucket Access — Who / Where / When</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              table_aggregated_field_wells {
                group_by {
                  date_dimension_field {
                    field_id = "ip-vend-tbl-detail.event_ts"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "ip-vend-tbl-detail.principal"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "principal_name"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "ip-vend-tbl-detail.source_ip"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "source_ip"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "ip-vend-tbl-detail.geo_city"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "geo_city"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "ip-vend-tbl-detail.geo_state"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "geo_state"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "ip-vend-tbl-detail.geo_county"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "geo_county"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "ip-vend-tbl-detail.eventname"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "eventname"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "ip-vend-tbl-detail.bucket"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "s3_bucket"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "ip-vend-tbl-detail.vendor"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "vendor"
                    }
                  }
                }
              }
            }
            sort_configuration {
              row_sort {
                field_sort {
                  field_id  = "ip-vend-tbl-detail.event_ts"
                  direction = "DESC"
                }
              }
            }
            table_options {
              cell_style {
                height = 30
              }
            }
          }
        }
      }

      visuals {
        geospatial_map_visual {
          visual_id = "ip-vend-geo"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Vendor Access — Geographic Origin (GeoLite2, approx)</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              geospatial_map_aggregated_field_wells {
                geospatial {
                  numerical_dimension_field {
                    field_id = "ip-vend-geo.lat"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "geo_lat"
                    }
                  }
                }
                geospatial {
                  numerical_dimension_field {
                    field_id = "ip-vend-geo.lon"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "geo_lon"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "ip-vend-geo.count"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
                # Color points by the credential identity (LabVendor-*) touching that
                # origin. Swap to `vendor` for the cleaned vendor slug.
                colors {
                  categorical_dimension_field {
                    field_id = "ip-vend-geo.principal"
                    column {
                      data_set_identifier = "CloudTrail Audit Dashboard"
                      column_name         = "principal_name"
                    }
                  }
                }
              }
            }
            map_style_options {
              base_map_style = "LIGHT_GRAY"
            }
            # POINT + explicit legend position — see the customer-map note above.
            point_style_options {
              selected_point_style = "POINT"
            }
            legend {
              visibility = "VISIBLE"
              position   = "BOTTOM"
              title {
                visibility = "VISIBLE"
              }
            }
            # Hover annotation: credential + event count at each origin point.
            tooltip {
              selected_tooltip_type = "DETAILED"
              tooltip_visibility    = "VISIBLE"
              field_base_tooltip {
                aggregation_visibility = "HIDDEN"
                tooltip_title_type     = "PRIMARY_VALUE"
                tooltip_fields {
                  field_tooltip_item {
                    field_id   = "ip-vend-geo.principal"
                    label      = "Credential"
                    visibility = "VISIBLE"
                  }
                }
                tooltip_fields {
                  field_tooltip_item {
                    field_id   = "ip-vend-geo.count"
                    label      = "Events"
                    visibility = "VISIBLE"
                  }
                }
              }
            }
          }
        }
      }

      layouts {
        configuration {
          grid_layout {
            elements {
              element_id   = "ip-cust-kpi-ips"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 8
              row_index    = 0
              row_span     = 6
            }
            elements {
              element_id   = "ip-cust-bar-ip"
              element_type = "VISUAL"
              column_index = 8
              column_span  = 28
              row_index    = 0
              row_span     = 6
            }
            elements {
              element_id   = "ip-cust-heat-hour"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 36
              row_index    = 6
              row_span     = 10
            }
            elements {
              element_id   = "ip-cust-tbl-detail"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 36
              row_index    = 16
              row_span     = 10
            }
            elements {
              element_id   = "ip-cust-geo"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 36
              row_index    = 26
              row_span     = 12
            }
            elements {
              element_id   = "ip-vend-kpi-ips"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 8
              row_index    = 38
              row_span     = 6
            }
            elements {
              element_id   = "ip-vend-bar-ip"
              element_type = "VISUAL"
              column_index = 8
              column_span  = 28
              row_index    = 38
              row_span     = 6
            }
            elements {
              element_id   = "ip-vend-heat-hour"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 36
              row_index    = 44
              row_span     = 10
            }
            elements {
              element_id   = "ip-vend-tbl-detail"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 36
              row_index    = 54
              row_span     = 10
            }
            elements {
              element_id   = "ip-vend-geo"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 36
              row_index    = 64
              row_span     = 12
            }
            canvas_size_options {
              screen_canvas_size_options {
                resize_option             = "FIXED"
                optimized_view_port_width = "1600px"
              }
            }
          }
        }
      }
      content_type = "INTERACTIVE"
    }

    # ════════════════════════════════════════════════════════════════════════
    # SHEET 6 — NAS ACCESS (Synology DS1823xs+ file events, own dataset)
    # ════════════════════════════════════════════════════════════════════════
    sheets {
      sheet_id = "nas"
      name     = "NAS Access"

      filter_controls {
        date_time_picker {
          filter_control_id = "ctl-nas-daterange"
          source_filter_id  = "f-nas-daterange"
          title             = "Date range"
          type              = "DATE_RANGE"
          display_options {
            date_time_format = "YYYY-MM-DD"
            title_options {
              visibility = "VISIBLE"
              font_configuration {}
            }
          }
        }
      }

      visuals {
        kpi_visual {
          visual_id = "nas-kpi-total"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Total NAS Events</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              trend_groups {
                date_dimension_field {
                  field_id = "nas-kpi-total.trend"
                  column {
                    data_set_identifier = "Synology NAS Access"
                    column_name         = "event_ts"
                  }
                  date_granularity = "DAY"
                  hierarchy_id     = "nas-kpi-total.trend"
                }
              }
              values {
                date_measure_field {
                  field_id = "nas-kpi-total.value"
                  column {
                    data_set_identifier = "Synology NAS Access"
                    column_name         = "event_ts"
                  }
                  aggregation_function = "COUNT"
                }
              }
            }
            kpi_options {
              primary_value_display_type = "ACTUAL"
              sparkline {
                visibility         = "VISIBLE"
                tooltip_visibility = "HIDDEN"
                type               = "LINE"
              }
            }
          }
          column_hierarchies {
            date_time_hierarchy {
              hierarchy_id = "nas-kpi-total.trend"
            }
          }
        }
      }

      visuals {
        kpi_visual {
          visual_id = "nas-kpi-users"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Active Users</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              trend_groups {
                date_dimension_field {
                  field_id = "nas-kpi-users.trend"
                  column {
                    data_set_identifier = "Synology NAS Access"
                    column_name         = "event_ts"
                  }
                  date_granularity = "DAY"
                  hierarchy_id     = "nas-kpi-users.trend"
                }
              }
              values {
                categorical_measure_field {
                  field_id = "nas-kpi-users.value"
                  column {
                    data_set_identifier = "Synology NAS Access"
                    column_name         = "username"
                  }
                  aggregation_function = "DISTINCT_COUNT"
                }
              }
            }
            kpi_options {
              primary_value_display_type = "ACTUAL"
              sparkline {
                visibility         = "VISIBLE"
                tooltip_visibility = "HIDDEN"
                type               = "LINE"
              }
            }
          }
          column_hierarchies {
            date_time_hierarchy {
              hierarchy_id = "nas-kpi-users.trend"
            }
          }
        }
      }

      visuals {
        kpi_visual {
          visual_id = "nas-kpi-paths"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Files Touched</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              trend_groups {
                date_dimension_field {
                  field_id = "nas-kpi-paths.trend"
                  column {
                    data_set_identifier = "Synology NAS Access"
                    column_name         = "event_ts"
                  }
                  date_granularity = "DAY"
                  hierarchy_id     = "nas-kpi-paths.trend"
                }
              }
              values {
                categorical_measure_field {
                  field_id = "nas-kpi-paths.value"
                  column {
                    data_set_identifier = "Synology NAS Access"
                    column_name         = "path"
                  }
                  aggregation_function = "DISTINCT_COUNT"
                }
              }
            }
            kpi_options {
              primary_value_display_type = "ACTUAL"
              sparkline {
                visibility         = "VISIBLE"
                tooltip_visibility = "HIDDEN"
                type               = "LINE"
              }
            }
          }
          column_hierarchies {
            date_time_hierarchy {
              hierarchy_id = "nas-kpi-paths.trend"
            }
          }
        }
      }

      visuals {
        line_chart_visual {
          visual_id = "nas-line-daily"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>NAS Activity Over Time</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              line_chart_aggregated_field_wells {
                category {
                  date_dimension_field {
                    field_id = "nas-line-daily.date"
                    column {
                      data_set_identifier = "Synology NAS Access"
                      column_name         = "event_ts"
                    }
                    hierarchy_id = "nas-line-daily.date"
                  }
                }
                values {
                  date_measure_field {
                    field_id = "nas-line-daily.count"
                    column {
                      data_set_identifier = "Synology NAS Access"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              category_sort {
                field_sort {
                  field_id  = "nas-line-daily.date"
                  direction = "ASC"
                }
              }
              category_items_limit_configuration {
                other_categories = "INCLUDE"
              }
              color_items_limit_configuration {
                other_categories = "INCLUDE"
              }
              small_multiples_limit_configuration {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
            }
            type = "LINE"
          }
          column_hierarchies {
            date_time_hierarchy {
              hierarchy_id = "nas-line-daily.date"
            }
          }
        }
      }

      visuals {
        pie_chart_visual {
          visual_id = "nas-donut-action"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Events by Action</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              pie_chart_aggregated_field_wells {
                category {
                  categorical_dimension_field {
                    field_id = "nas-donut-action.action"
                    column {
                      data_set_identifier = "Synology NAS Access"
                      column_name         = "action"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "nas-donut-action.count"
                    column {
                      data_set_identifier = "Synology NAS Access"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              category_sort {
                field_sort {
                  field_id  = "nas-donut-action.count"
                  direction = "DESC"
                }
              }
              category_items_limit {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
              small_multiples_limit_configuration {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
            }
            donut_options {
              arc_options {
                arc_thickness = "MEDIUM"
              }
            }
            legend {
              visibility = "VISIBLE"
            }
          }
        }
      }

      visuals {
        bar_chart_visual {
          visual_id = "nas-bar-users"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Top Users</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              bar_chart_aggregated_field_wells {
                category {
                  categorical_dimension_field {
                    field_id = "nas-bar-users.username"
                    column {
                      data_set_identifier = "Synology NAS Access"
                      column_name         = "username"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "nas-bar-users.count"
                    column {
                      data_set_identifier = "Synology NAS Access"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              category_sort {
                field_sort {
                  field_id  = "nas-bar-users.count"
                  direction = "DESC"
                }
              }
              category_items_limit {
                items_limit      = 15
                other_categories = "INCLUDE"
              }
              color_items_limit {
                other_categories = "INCLUDE"
              }
              small_multiples_limit_configuration {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
            }
            orientation = "HORIZONTAL"
          }
        }
      }

      visuals {
        bar_chart_visual {
          visual_id = "nas-bar-paths"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Top Paths</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              bar_chart_aggregated_field_wells {
                category {
                  categorical_dimension_field {
                    field_id = "nas-bar-paths.path"
                    column {
                      data_set_identifier = "Synology NAS Access"
                      column_name         = "path"
                    }
                  }
                }
                values {
                  date_measure_field {
                    field_id = "nas-bar-paths.count"
                    column {
                      data_set_identifier = "Synology NAS Access"
                      column_name         = "event_ts"
                    }
                    aggregation_function = "COUNT"
                  }
                }
              }
            }
            sort_configuration {
              category_sort {
                field_sort {
                  field_id  = "nas-bar-paths.count"
                  direction = "DESC"
                }
              }
              category_items_limit {
                items_limit      = 15
                other_categories = "INCLUDE"
              }
              color_items_limit {
                other_categories = "INCLUDE"
              }
              small_multiples_limit_configuration {
                items_limit      = 10
                other_categories = "INCLUDE"
              }
            }
            orientation = "HORIZONTAL"
          }
        }
      }

      visuals {
        table_visual {
          visual_id = "nas-tbl-recent"
          title {
            visibility = "VISIBLE"
            format_text {
              rich_text = "<visual-title>Recent File Events</visual-title>"
            }
          }
          chart_configuration {
            field_wells {
              table_aggregated_field_wells {
                group_by {
                  date_dimension_field {
                    field_id = "nas-tbl-recent.event_ts"
                    column {
                      data_set_identifier = "Synology NAS Access"
                      column_name         = "event_ts"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "nas-tbl-recent.username"
                    column {
                      data_set_identifier = "Synology NAS Access"
                      column_name         = "username"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "nas-tbl-recent.action"
                    column {
                      data_set_identifier = "Synology NAS Access"
                      column_name         = "action"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "nas-tbl-recent.proto"
                    column {
                      data_set_identifier = "Synology NAS Access"
                      column_name         = "proto"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "nas-tbl-recent.src_ip"
                    column {
                      data_set_identifier = "Synology NAS Access"
                      column_name         = "src_ip"
                    }
                  }
                }
                group_by {
                  categorical_dimension_field {
                    field_id = "nas-tbl-recent.path"
                    column {
                      data_set_identifier = "Synology NAS Access"
                      column_name         = "path"
                    }
                  }
                }
              }
            }
            sort_configuration {
              row_sort {
                field_sort {
                  field_id  = "nas-tbl-recent.event_ts"
                  direction = "DESC"
                }
              }
            }
          }
        }
      }

      layouts {
        configuration {
          grid_layout {
            elements {
              element_id   = "nas-kpi-total"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 12
              row_index    = 0
              row_span     = 4
            }
            elements {
              element_id   = "nas-kpi-users"
              element_type = "VISUAL"
              column_index = 12
              column_span  = 12
              row_index    = 0
              row_span     = 4
            }
            elements {
              element_id   = "nas-kpi-paths"
              element_type = "VISUAL"
              column_index = 24
              column_span  = 12
              row_index    = 0
              row_span     = 4
            }
            elements {
              element_id   = "nas-line-daily"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 24
              row_index    = 4
              row_span     = 8
            }
            elements {
              element_id   = "nas-donut-action"
              element_type = "VISUAL"
              column_index = 24
              column_span  = 12
              row_index    = 4
              row_span     = 8
            }
            elements {
              element_id   = "nas-bar-users"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 18
              row_index    = 12
              row_span     = 8
            }
            elements {
              element_id   = "nas-bar-paths"
              element_type = "VISUAL"
              column_index = 18
              column_span  = 18
              row_index    = 12
              row_span     = 8
            }
            elements {
              element_id   = "nas-tbl-recent"
              element_type = "VISUAL"
              column_index = 0
              column_span  = 36
              row_index    = 20
              row_span     = 8
            }
            canvas_size_options {
              screen_canvas_size_options {
                resize_option             = "FIXED"
                optimized_view_port_width = "1600px"
              }
            }
          }
        }
      }
      content_type = "INTERACTIVE"
    }

    # ════════════════════════════════════════════════════════════════════════
    # FILTER GROUPS — scoped per-visual / per-sheet
    # ════════════════════════════════════════════════════════════════════════

    # Security: error-code bar shows only rows that actually errored (drops the
    # null/blank errorcode bucket).
    filter_groups {
      filter_group_id = "fg-sec-errornotnull"
      filters {
        category_filter {
          filter_id = "f-sec-errornotnull"
          column {
            data_set_identifier = "CloudTrail Audit Dashboard"
            column_name         = "errorcode"
          }
          configuration {
            custom_filter_configuration {
              match_operator = "DOES_NOT_EQUAL"
              category_value = "__none__"
              null_option    = "NON_NULLS_ONLY"
            }
          }
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id   = "security"
            scope      = "SELECTED_VISUALS"
            visual_ids = ["sec-bar-errorcodes"]
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    # Security: "Top Principals by Failures" — only events that errored.
    filter_groups {
      filter_group_id = "fg-sec-denied"
      filters {
        numeric_equality_filter {
          filter_id = "f-sec-denied"
          column {
            data_set_identifier = "CloudTrail Audit Dashboard"
            column_name         = "is_error"
          }
          match_operator = "EQUALS"
          value          = 1
          null_option    = "NON_NULLS_ONLY"
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id   = "security"
            scope      = "SELECTED_VISUALS"
            visual_ids = ["sec-bar-denied-principals"]
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    # Security: console-login table.
    filter_groups {
      filter_group_id = "fg-sec-console"
      filters {
        category_filter {
          filter_id = "f-sec-console"
          column {
            data_set_identifier = "CloudTrail Audit Dashboard"
            column_name         = "eventname"
          }
          configuration {
            custom_filter_list_configuration {
              match_operator  = "CONTAINS"
              category_values = ["ConsoleLogin"]
              null_option     = "NON_NULLS_ONLY"
            }
          }
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id   = "security"
            scope      = "SELECTED_VISUALS"
            visual_ids = ["sec-tbl-console"]
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    # Security: root-account table.
    filter_groups {
      filter_group_id = "fg-sec-root"
      filters {
        category_filter {
          filter_id = "f-sec-root"
          column {
            data_set_identifier = "CloudTrail Audit Dashboard"
            column_name         = "principal_type"
          }
          configuration {
            custom_filter_list_configuration {
              match_operator  = "CONTAINS"
              category_values = ["Root"]
              null_option     = "NON_NULLS_ONLY"
            }
          }
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id   = "security"
            scope      = "SELECTED_VISUALS"
            visual_ids = ["sec-tbl-root"]
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    # Security: IAM + KMS admin-change table.
    filter_groups {
      filter_group_id = "fg-sec-iamkms"
      filters {
        category_filter {
          filter_id = "f-sec-iamkms"
          column {
            data_set_identifier = "CloudTrail Audit Dashboard"
            column_name         = "eventname"
          }
          configuration {
            custom_filter_list_configuration {
              match_operator  = "CONTAINS"
              category_values = local.iam_kms_events
              null_option     = "NON_NULLS_ONLY"
            }
          }
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id   = "security"
            scope      = "SELECTED_VISUALS"
            visual_ids = ["sec-tbl-iam-kms"]
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    # PHI sheet: restrict the WHOLE sheet to S3 object-level operations.
    filter_groups {
      filter_group_id = "fg-phi-sheet"
      filters {
        category_filter {
          filter_id = "f-phi-sheet"
          column {
            data_set_identifier = "CloudTrail Audit Dashboard"
            column_name         = "eventname"
          }
          configuration {
            custom_filter_list_configuration {
              match_operator  = "CONTAINS"
              category_values = local.s3_object_events
              null_option     = "NON_NULLS_ONLY"
            }
          }
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id = "phi"
            scope    = "ALL_VISUALS"
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    # PHI: read KPI (combines with the sheet filter → GetObject only).
    filter_groups {
      filter_group_id = "fg-phi-read"
      filters {
        category_filter {
          filter_id = "f-phi-read"
          column {
            data_set_identifier = "CloudTrail Audit Dashboard"
            column_name         = "eventname"
          }
          configuration {
            custom_filter_list_configuration {
              match_operator  = "CONTAINS"
              category_values = ["GetObject"]
              null_option     = "NON_NULLS_ONLY"
            }
          }
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id   = "phi"
            scope      = "SELECTED_VISUALS"
            visual_ids = ["phi-kpi-read"]
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    # PHI: write KPI.
    filter_groups {
      filter_group_id = "fg-phi-write"
      filters {
        category_filter {
          filter_id = "f-phi-write"
          column {
            data_set_identifier = "CloudTrail Audit Dashboard"
            column_name         = "eventname"
          }
          configuration {
            custom_filter_list_configuration {
              match_operator  = "CONTAINS"
              category_values = ["PutObject"]
              null_option     = "NON_NULLS_ONLY"
            }
          }
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id   = "phi"
            scope      = "SELECTED_VISUALS"
            visual_ids = ["phi-kpi-write"]
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    # PHI: delete KPI + deletions table.
    filter_groups {
      filter_group_id = "fg-phi-delete"
      filters {
        category_filter {
          filter_id = "f-phi-delete"
          column {
            data_set_identifier = "CloudTrail Audit Dashboard"
            column_name         = "eventname"
          }
          configuration {
            custom_filter_list_configuration {
              match_operator  = "CONTAINS"
              category_values = ["DeleteObject"]
              null_option     = "NON_NULLS_ONLY"
            }
          }
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id   = "phi"
            scope      = "SELECTED_VISUALS"
            visual_ids = ["phi-kpi-delete", "phi-tbl-deletes"]
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    # Customers: drop the null-customer bucket (management events not tied to a
    # researcher) across all customer-scoped visuals. Filters on the never-NULL
    # is_customer flag (numeric equality, fg-sec-denied idiom) — the previous
    # category filter with null_option=NON_NULLS_ONLY still rendered a null bar.
    filter_groups {
      filter_group_id = "fg-cust-notnull"
      filters {
        numeric_equality_filter {
          filter_id = "f-cust-notnull"
          column {
            data_set_identifier = "CloudTrail Audit Dashboard"
            column_name         = "is_customer"
          }
          match_operator = "EQUALS"
          value          = 1
          null_option    = "NON_NULLS_ONLY"
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id   = "customers"
            scope      = "SELECTED_VISUALS"
            visual_ids = ["cust-kpi-active", "cust-bar-activity", "cust-line-trend", "cust-tbl-detail", "cust-tbl-errors"]
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    # Customers: "Top Customers by Data Access" — non-null customer AND S3 object ops.
    # Two SEPARATE groups (same scope) so QuickSight ANDs them; one group with both
    # filters would OR (see the fg-ip-customer-* note) and let null-customer rows back in.
    filter_groups {
      filter_group_id = "fg-cust-datavol-customer"
      filters {
        numeric_equality_filter {
          filter_id = "f-cust-datavol-customer"
          column {
            data_set_identifier = "CloudTrail Audit Dashboard"
            column_name         = "is_customer"
          }
          match_operator = "EQUALS"
          value          = 1
          null_option    = "NON_NULLS_ONLY"
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id   = "customers"
            scope      = "SELECTED_VISUALS"
            visual_ids = ["cust-bar-datavol"]
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    filter_groups {
      filter_group_id = "fg-cust-datavol-events"
      filters {
        category_filter {
          filter_id = "f-cust-datavol-events"
          column {
            data_set_identifier = "CloudTrail Audit Dashboard"
            column_name         = "eventname"
          }
          configuration {
            custom_filter_list_configuration {
              match_operator  = "CONTAINS"
              category_values = local.s3_object_events
              null_option     = "NON_NULLS_ONLY"
            }
          }
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id   = "customers"
            scope      = "SELECTED_VISUALS"
            visual_ids = ["cust-bar-datavol"]
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    # Source IP Access — customer block: S3 activity performed WITH a LabCustomer
    # credential. Three conditions, AND-combined:
    #   is_customer_cred=1 — principal IS LabCustomer-* (render-proof numeric flag, NOT
    #                        the bucket-inclusive is_customer, which also tags backend
    #                        sync / provisioner writes and AWS-service principals — the
    #                        *.amazonaws.com source_ip noise).
    #   has_s3_bucket=1    — drop bucket-less S3 rows (e.g. ListBuckets) without a null group.
    #   eventsource=s3     — S3 data/control plane only.
    #
    # IMPORTANT: these are THREE separate filter_groups, NOT one group with three filters.
    # QuickSight combines filters *within* a group with OR, and *across* groups (same
    # scope) with AND. One group would OR the conditions, so every S3-on-a-bucket row
    # (has_s3_bucket=1 / eventsource=s3) would pass regardless of the credential flag —
    # which is exactly the null-customer / operational-bucket noise we are removing.
    filter_groups {
      filter_group_id = "fg-ip-customer-cred"
      filters {
        numeric_equality_filter {
          filter_id = "f-ip-customer-flag"
          column {
            data_set_identifier = "CloudTrail Audit Dashboard"
            column_name         = "is_customer_cred"
          }
          match_operator = "EQUALS"
          value          = 1
          null_option    = "NON_NULLS_ONLY"
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id   = "ipaccess"
            scope      = "SELECTED_VISUALS"
            visual_ids = local.ip_customer_visuals
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    filter_groups {
      filter_group_id = "fg-ip-customer-hasbucket"
      filters {
        numeric_equality_filter {
          filter_id = "f-ip-customer-hasbucket"
          column {
            data_set_identifier = "CloudTrail Audit Dashboard"
            column_name         = "has_s3_bucket"
          }
          match_operator = "EQUALS"
          value          = 1
          null_option    = "NON_NULLS_ONLY"
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id   = "ipaccess"
            scope      = "SELECTED_VISUALS"
            visual_ids = local.ip_customer_visuals
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    filter_groups {
      filter_group_id = "fg-ip-customer-s3"
      filters {
        category_filter {
          filter_id = "f-ip-customer-s3"
          column {
            data_set_identifier = "CloudTrail Audit Dashboard"
            column_name         = "eventsource"
          }
          configuration {
            custom_filter_list_configuration {
              match_operator  = "CONTAINS"
              category_values = ["s3.amazonaws.com"]
              null_option     = "NON_NULLS_ONLY"
            }
          }
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id   = "ipaccess"
            scope      = "SELECTED_VISUALS"
            visual_ids = local.ip_customer_visuals
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    # Source IP Access — vendor block: same credential-precise shape on is_vendor_cred=1
    # (principal IS LabVendor-*) AND has_s3_bucket=1 AND eventsource=s3. Three separate
    # groups for the same AND-not-OR reason documented on the customer block above.
    filter_groups {
      filter_group_id = "fg-ip-vendor-cred"
      filters {
        numeric_equality_filter {
          filter_id = "f-ip-vendor-flag"
          column {
            data_set_identifier = "CloudTrail Audit Dashboard"
            column_name         = "is_vendor_cred"
          }
          match_operator = "EQUALS"
          value          = 1
          null_option    = "NON_NULLS_ONLY"
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id   = "ipaccess"
            scope      = "SELECTED_VISUALS"
            visual_ids = local.ip_vendor_visuals
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    filter_groups {
      filter_group_id = "fg-ip-vendor-hasbucket"
      filters {
        numeric_equality_filter {
          filter_id = "f-ip-vendor-hasbucket"
          column {
            data_set_identifier = "CloudTrail Audit Dashboard"
            column_name         = "has_s3_bucket"
          }
          match_operator = "EQUALS"
          value          = 1
          null_option    = "NON_NULLS_ONLY"
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id   = "ipaccess"
            scope      = "SELECTED_VISUALS"
            visual_ids = local.ip_vendor_visuals
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    filter_groups {
      filter_group_id = "fg-ip-vendor-s3"
      filters {
        category_filter {
          filter_id = "f-ip-vendor-s3"
          column {
            data_set_identifier = "CloudTrail Audit Dashboard"
            column_name         = "eventsource"
          }
          configuration {
            custom_filter_list_configuration {
              match_operator  = "CONTAINS"
              category_values = ["s3.amazonaws.com"]
              null_option     = "NON_NULLS_ONLY"
            }
          }
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id   = "ipaccess"
            scope      = "SELECTED_VISUALS"
            visual_ids = local.ip_vendor_visuals
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    # ── Per-sheet date-range filters, each driven by the sheet's date_time_picker ──
    # Unbounded by default (null_option ALL_VALUES, no static range) so the whole
    # 90-day dataset shows until the user narrows it with the control.
    filter_groups {
      filter_group_id = "fg-ov-daterange"
      filters {
        time_range_filter {
          filter_id = "f-ov-daterange"
          column {
            data_set_identifier = "CloudTrail Audit Dashboard"
            column_name         = "event_ts"
          }
          null_option      = "ALL_VALUES"
          time_granularity = "MINUTE"
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id = "overview"
            scope    = "ALL_VISUALS"
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    filter_groups {
      filter_group_id = "fg-sec-daterange"
      filters {
        time_range_filter {
          filter_id = "f-sec-daterange"
          column {
            data_set_identifier = "CloudTrail Audit Dashboard"
            column_name         = "event_ts"
          }
          null_option      = "ALL_VALUES"
          time_granularity = "MINUTE"
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id = "security"
            scope    = "ALL_VISUALS"
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    filter_groups {
      filter_group_id = "fg-phi-daterange"
      filters {
        time_range_filter {
          filter_id = "f-phi-daterange"
          column {
            data_set_identifier = "CloudTrail Audit Dashboard"
            column_name         = "event_ts"
          }
          null_option      = "ALL_VALUES"
          time_granularity = "MINUTE"
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id = "phi"
            scope    = "ALL_VISUALS"
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    filter_groups {
      filter_group_id = "fg-cust-daterange"
      filters {
        time_range_filter {
          filter_id = "f-cust-daterange"
          column {
            data_set_identifier = "CloudTrail Audit Dashboard"
            column_name         = "event_ts"
          }
          null_option      = "ALL_VALUES"
          time_granularity = "MINUTE"
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id = "customers"
            scope    = "ALL_VISUALS"
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    filter_groups {
      filter_group_id = "fg-ip-daterange"
      filters {
        time_range_filter {
          filter_id = "f-ip-daterange"
          column {
            data_set_identifier = "CloudTrail Audit Dashboard"
            column_name         = "event_ts"
          }
          null_option      = "ALL_VALUES"
          time_granularity = "MINUTE"
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id = "ipaccess"
            scope    = "ALL_VISUALS"
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    filter_groups {
      filter_group_id = "fg-nas-daterange"
      filters {
        time_range_filter {
          filter_id = "f-nas-daterange"
          column {
            data_set_identifier = "Synology NAS Access"
            column_name         = "event_ts"
          }
          null_option      = "ALL_VALUES"
          time_granularity = "MINUTE"
        }
      }
      scope_configuration {
        selected_sheets {
          sheet_visual_scoping_configurations {
            sheet_id = "nas"
            scope    = "ALL_VISUALS"
          }
        }
      }
      status        = "ENABLED"
      cross_dataset = "SINGLE_DATASET"
    }

    analysis_defaults {
      default_new_sheet_configuration {
        interactive_layout_configuration {
          grid {
            canvas_size_options {
              screen_canvas_size_options {
                resize_option             = "FIXED"
                optimized_view_port_width = "1600px"
              }
            }
          }
        }
        sheet_content_type = "INTERACTIVE"
      }
    }
  }

  lifecycle {
    ignore_changes = [permissions]
  }
}
