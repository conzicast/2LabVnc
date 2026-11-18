param(
  [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Drawing

$iconSizes = @(16, 20, 24, 32, 40, 48, 64, 128, 256)
$brandRed = [System.Drawing.ColorTranslator]::FromHtml('#E30613')
$brandDarkRed = [System.Drawing.ColorTranslator]::FromHtml('#A4000B')
$securityGreen = [System.Drawing.ColorTranslator]::FromHtml('#20A447')
$white = [System.Drawing.Color]::White
$monogramRed = [System.Drawing.ColorTranslator]::FromHtml('#B90018')
$serverArtwork = Join-Path $PSScriptRoot 'server-large.png'

function Draw-Monogram {
  param(
    [System.Drawing.Graphics]$Graphics,
    [int]$Size,
    [string]$Variant
  )

  # Snap the approved 16-pixel artwork to the output grid before filling.
  $unit = $Size / 16.0
  $Graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::None
  $tileColor = if ($Variant -eq 'disabled') { $brandDarkRed } else { $monogramRed }
  $tileBrush = [System.Drawing.SolidBrush]::new($tileColor)
  $whiteBrush = [System.Drawing.Brushes]::White
  try {
    $shapes = @(
      @{ Brush = $tileBrush; Vertices = @(1,0, 15,0, 15,1, 16,1, 16,15, 15,15, 15,16, 1,16, 1,15, 0,15, 0,1, 1,1) }
      @{ Brush = $whiteBrush; Vertices = @(1,1, 4,1, 4,12, 15,12, 15,15, 1,15) }
      @{ Brush = $whiteBrush; Vertices = @(7,2, 13,2, 13,3, 14,3, 14,6, 12,6, 12,7, 10,7, 10,8, 8,8, 8,9, 14,9, 14,11, 6,11, 6,7, 8,7, 8,6, 10,6, 10,5, 12,5, 12,4, 8,4, 8,5, 6,5, 6,3, 7,3) }
    )
    foreach ($shape in $shapes) {
      [System.Drawing.Point[]]$points = for ($index = 0; $index -lt $shape.Vertices.Count; $index += 2) {
        [System.Drawing.Point]::new(
          [Math]::Round($shape.Vertices[$index] * $unit),
          [Math]::Round($shape.Vertices[$index + 1] * $unit))
      }
      $Graphics.FillPolygon($shape.Brush, $points)
    }
  } finally {
    $tileBrush.Dispose()
  }

  if ($Variant -in @('connected', 'disabled')) {
    Draw-TrayBadge $Graphics $Size $Variant
  }
}

function Draw-TrayBadge {
  param([System.Drawing.Graphics]$Graphics, [int]$Size, [string]$Variant)

  # Cover only the end of the L, leaving the 2 intact at tray sizes.
  $badgeSize = [int][Math]::Round($Size * 5 / 16.0)
  $left = $Size - $badgeSize
  $Graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
  if ($Variant -eq 'connected') {
    $greenBrush = [System.Drawing.SolidBrush]::new($securityGreen)
    $badgeOutline = [System.Drawing.Pen]::new([System.Drawing.Color]::White, $Size / 20.0)
    [System.Drawing.PointF[]]$shield = @(
      [System.Drawing.PointF]::new($left + $badgeSize * 0.5, $left + 0.5),
      [System.Drawing.PointF]::new($Size - 0.5, $left + $badgeSize * 0.25),
      [System.Drawing.PointF]::new($Size - 0.8, $left + $badgeSize * 0.65),
      [System.Drawing.PointF]::new($left + $badgeSize * 0.5, $Size - 0.5),
      [System.Drawing.PointF]::new($left + 0.8, $left + $badgeSize * 0.65),
      [System.Drawing.PointF]::new($left + 0.5, $left + $badgeSize * 0.25))
    try {
      $Graphics.FillPolygon($greenBrush, $shield)
      $Graphics.DrawPolygon($badgeOutline, $shield)
    } finally {
      $badgeOutline.Dispose()
      $greenBrush.Dispose()
    }
  } else {
    $Graphics.FillEllipse([System.Drawing.Brushes]::White, $left, $left, $badgeSize, $badgeSize)
    $inset = [Math]::Max(1, $Size / 16.0)
    $inside = $badgeSize - 2 * $inset
    $Graphics.FillEllipse([System.Drawing.Brushes]::DimGray, $left + $inset, $left + $inset, $inside, $inside)
    $slash = [System.Drawing.Pen]::new([System.Drawing.Color]::White, $inset)
    try {
      $Graphics.DrawLine($slash, $left + $inset, $left + $inset, $Size - $inset, $Size - $inset)
    } finally {
      $slash.Dispose()
    }
  }
}

function New-RoundedRectanglePath {
  param(
    [System.Drawing.RectangleF]$Bounds,
    [float]$Radius
  )

  $diameter = $Radius * 2
  $path = [System.Drawing.Drawing2D.GraphicsPath]::new()
  $path.AddArc($Bounds.X, $Bounds.Y, $diameter, $diameter, 180, 90)
  $path.AddArc($Bounds.Right - $diameter, $Bounds.Y, $diameter, $diameter, 270, 90)
  $path.AddArc($Bounds.Right - $diameter, $Bounds.Bottom - $diameter, $diameter, $diameter, 0, 90)
  $path.AddArc($Bounds.X, $Bounds.Bottom - $diameter, $diameter, $diameter, 90, 90)
  $path.CloseFigure()
  return $path
}

function Draw-Monitor {
  param(
    [System.Drawing.Graphics]$Graphics,
    [int]$Size,
    [System.Drawing.Brush]$Brush
  )

  $stroke = [Math]::Max(1.5, $Size * 0.045)
  $monitorBounds = [System.Drawing.RectangleF]::new(
    $Size * 0.10, $Size * 0.16, $Size * 0.80, $Size * 0.59)
  $monitorPath = New-RoundedRectanglePath $monitorBounds ($Size * 0.07)
  $pen = [System.Drawing.Pen]::new($Brush, $stroke)
  $pen.Alignment = [System.Drawing.Drawing2D.PenAlignment]::Inset
  $Graphics.DrawPath($pen, $monitorPath)

  $standWidth = $Size * 0.27
  $standHeight = $Size * 0.055
  $standX = ($Size - $standWidth) / 2
  $standY = $Size * 0.80
  $Graphics.FillRectangle($Brush, $Size * 0.47, $Size * 0.74,
                          $Size * 0.06, $Size * 0.09)
  $standBounds = [System.Drawing.RectangleF]::new(
    $standX, $standY, $standWidth, $standHeight)
  $standPath = New-RoundedRectanglePath $standBounds ($standHeight / 2)
  $Graphics.FillPath($Brush, $standPath)

  $pen.Dispose()
  $monitorPath.Dispose()
  $standPath.Dispose()
}

function Draw-ProductName {
  param(
    [System.Drawing.Graphics]$Graphics,
    [int]$Size,
    [System.Drawing.Brush]$Brush
  )

  $label = if ($Size -lt 32) { '2L' } else { '2Lab' }
  $fontSize = if ($Size -lt 32) { $Size * 0.50 } else { $Size * 0.245 }
  $font = [System.Drawing.Font]::new(
    'Georgia', $fontSize,
    [System.Drawing.FontStyle]::Bold,
    [System.Drawing.GraphicsUnit]::Pixel)
  $format = [System.Drawing.StringFormat]::new()
  $format.Alignment = [System.Drawing.StringAlignment]::Center
  $format.LineAlignment = [System.Drawing.StringAlignment]::Center
  $format.FormatFlags = [System.Drawing.StringFormatFlags]::NoWrap
  $textBounds = if ($Size -lt 32) {
    [System.Drawing.RectangleF]::new(0, $Size * 0.18, $Size, $Size * 0.58)
  } else {
    [System.Drawing.RectangleF]::new($Size * 0.13, $Size * 0.25,
                                     $Size * 0.74, $Size * 0.36)
  }
  $Graphics.DrawString($label, $font, $Brush, $textBounds, $format)
  $format.Dispose()
  $font.Dispose()
}

function Draw-SecurityShield {
  param(
    [System.Drawing.Graphics]$Graphics,
    [int]$Size,
    [System.Drawing.Brush]$GreenBrush,
    [System.Drawing.Brush]$WhiteBrush
  )

  $left = $Size * 0.67
  $top = $Size * 0.57
  $width = $Size * 0.24
  $height = $Size * 0.27
  [System.Drawing.PointF[]]$points = @(
    [System.Drawing.PointF]::new($left + $width * 0.50, $top),
    [System.Drawing.PointF]::new($left + $width, $top + $height * 0.18),
    [System.Drawing.PointF]::new($left + $width * 0.92, $top + $height * 0.68),
    [System.Drawing.PointF]::new($left + $width * 0.50, $top + $height),
    [System.Drawing.PointF]::new($left + $width * 0.08, $top + $height * 0.68),
    [System.Drawing.PointF]::new($left, $top + $height * 0.18)
  )
  $Graphics.FillPolygon($GreenBrush, $points)

  $keyholeRadius = [Math]::Max(1.0, $Size * 0.022)
  $keyholeX = $left + $width * 0.50
  $keyholeY = $top + $height * 0.45
  $Graphics.FillEllipse($WhiteBrush,
    $keyholeX - $keyholeRadius, $keyholeY - $keyholeRadius,
    $keyholeRadius * 2, $keyholeRadius * 2)
  $Graphics.FillRectangle($WhiteBrush,
    $keyholeX - $keyholeRadius * 0.45, $keyholeY,
    $keyholeRadius * 0.90, $height * 0.22)
}

function Draw-StateMark {
  param(
    [System.Drawing.Graphics]$Graphics,
    [int]$Size,
    [string]$Variant,
    [System.Drawing.Brush]$WhiteBrush
  )

  if ($Variant -eq 'connected') {
    $pen = [System.Drawing.Pen]::new($WhiteBrush, [Math]::Max(1.5, $Size * 0.025))
    $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    [System.Drawing.PointF[]]$checkPoints = @(
      [System.Drawing.PointF]::new($Size * 0.72, $Size * 0.70),
      [System.Drawing.PointF]::new($Size * 0.76, $Size * 0.74),
      [System.Drawing.PointF]::new($Size * 0.84, $Size * 0.64)
    )
    $Graphics.DrawLines($pen, $checkPoints)
    $pen.Dispose()
  } elseif ($Variant -eq 'disabled') {
    $pen = [System.Drawing.Pen]::new($WhiteBrush, [Math]::Max(2.0, $Size * 0.055))
    $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    $Graphics.DrawLine($pen, $Size * 0.20, $Size * 0.20,
                       $Size * 0.80, $Size * 0.80)
    $pen.Dispose()
  }
}

function New-IconBitmap {
  param(
    [int]$Size,
    [ValidateSet('viewer', 'server', 'connected', 'disabled')]
    [string]$Variant
  )

  $bitmap = [System.Drawing.Bitmap]::new(
    $Size, $Size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
  $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
  $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
  $graphics.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
  $graphics.Clear([System.Drawing.Color]::Transparent)

  if ($Size -lt 128) {
    Draw-Monogram $graphics $Size $Variant
    $graphics.Dispose()
    return $bitmap
  }
  if ($Variant -eq 'server') {
    $source = [System.Drawing.Image]::FromFile($serverArtwork)
    try {
      $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
      $graphics.DrawImage($source, 0, 0, $Size, $Size)
    } finally {
      $source.Dispose()
      $graphics.Dispose()
    }
    return $bitmap
  }

  $backgroundColor = if ($Variant -eq 'disabled') { $brandDarkRed } else { $brandRed }
  $backgroundBrush = [System.Drawing.SolidBrush]::new($backgroundColor)
  $whiteBrush = [System.Drawing.SolidBrush]::new($white)
  $greenBrush = [System.Drawing.SolidBrush]::new($securityGreen)
  $tileBounds = [System.Drawing.RectangleF]::new(0, 0, $Size - 1, $Size - 1)
  $tilePath = New-RoundedRectanglePath $tileBounds ($Size * 0.14)
  $graphics.FillPath($backgroundBrush, $tilePath)

  Draw-Monitor $graphics $Size $whiteBrush
  Draw-ProductName $graphics $Size $whiteBrush
  if ($Variant -ne 'viewer' -and $Variant -ne 'disabled') {
    Draw-SecurityShield $graphics $Size $greenBrush $whiteBrush
  }
  Draw-StateMark $graphics $Size $Variant $whiteBrush

  $tilePath.Dispose()
  $backgroundBrush.Dispose()
  $whiteBrush.Dispose()
  $greenBrush.Dispose()
  $graphics.Dispose()
  return $bitmap
}

function Write-MultiSizeIcon {
  param(
    [string]$Path,
    [ValidateSet('viewer', 'server', 'connected', 'disabled')]
    [string]$Variant
  )

  $images = @()
  foreach ($size in $iconSizes) {
    $bitmap = New-IconBitmap $size $Variant
    $stream = [System.IO.MemoryStream]::new()
    $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
    $images += [pscustomobject]@{
      Size = $size
      Bytes = $stream.ToArray()
    }
    $stream.Dispose()
    $bitmap.Dispose()
  }

  $output = [System.IO.File]::Create($Path)
  $writer = [System.IO.BinaryWriter]::new($output)
  $writer.Write([uint16]0)
  $writer.Write([uint16]1)
  $writer.Write([uint16]$images.Count)
  $dataOffset = 6 + (16 * $images.Count)
  foreach ($image in $images) {
    $dimension = if ($image.Size -eq 256) { 0 } else { $image.Size }
    $writer.Write([byte]$dimension)
    $writer.Write([byte]$dimension)
    $writer.Write([byte]0)
    $writer.Write([byte]0)
    $writer.Write([uint16]1)
    $writer.Write([uint16]32)
    $writer.Write([uint32]$image.Bytes.Length)
    $writer.Write([uint32]$dataOffset)
    $dataOffset += $image.Bytes.Length
  }
  foreach ($image in $images) {
    $writer.Write($image.Bytes)
  }
  $writer.Dispose()
  $output.Dispose()
}

function Write-Preview {
  param(
    [string]$Path,
    [ValidateSet('viewer', 'server', 'connected', 'disabled')]
    [string]$Variant
  )

  $bitmap = New-IconBitmap 256 $Variant
  $bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
  $bitmap.Dispose()
}

function Write-AboutBitmap {
  param(
    [string]$Path,
    [int]$Width,
    [int]$Height,
    [ValidateSet('viewer', 'server')]
    [string]$Variant
  )

  $canvas = [System.Drawing.Bitmap]::new($Width, $Height)
  $graphics = [System.Drawing.Graphics]::FromImage($canvas)
  $graphics.Clear([System.Drawing.Color]::White)
  $graphics.InterpolationMode =
    [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
  $side = [Math]::Min($Width, $Height)
  $source = New-IconBitmap $side $Variant
  $left = [int](($Width - $side) / 2)
  $graphics.DrawImage($source, $left, 0, $side, $side)
  $canvas.Save($Path, [System.Drawing.Imaging.ImageFormat]::Bmp)
  $source.Dispose()
  $graphics.Dispose()
  $canvas.Dispose()
}

$outputDirectory = Join-Path $PSScriptRoot 'generated'
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null

$variants = @('viewer', 'server', 'connected', 'disabled')
foreach ($variant in $variants) {
  Write-MultiSizeIcon (Join-Path $outputDirectory "2labvnc-$variant.ico") $variant
  Write-Preview (Join-Path $outputDirectory "2labvnc-$variant.png") $variant
}

Write-AboutBitmap `
  (Join-Path $ProjectRoot 'tvnserver\res\tightvnc.bmp') `
  60 55 'server'
Write-AboutBitmap `
  (Join-Path $ProjectRoot 'tvnviewer\res\tightvnc.bmp') `
  60 55 'viewer'
Write-AboutBitmap `
  (Join-Path $ProjectRoot 'tvnviewer\res\tightvnc48.bmp') `
  32 30 'viewer'

$copyTargets = @{
  (Join-Path $ProjectRoot 'tvnviewer\res\appicon.ico') = 'viewer'
  (Join-Path $ProjectRoot 'tvnserver\res\idle.ico') = 'server'
  (Join-Path $ProjectRoot 'tvnserver\res\connected.ico') = 'connected'
  (Join-Path $ProjectRoot 'tvnserver\res\disabled.ico') = 'disabled'
  (Join-Path $ProjectRoot 'wix-installer\tvnserver.ico') = 'server'
  (Join-Path $ProjectRoot 'wix-installer\vncviewer.ico') = 'viewer'
}
foreach ($target in $copyTargets.Keys) {
  Copy-Item -LiteralPath (Join-Path $outputDirectory "2labvnc-$($copyTargets[$target]).ico") `
            -Destination $target -Force
}

Write-Output "Generated flat 2LabVnc icon family in $outputDirectory"
