import * as React from 'react';
import PropTypes from 'prop-types';
import {ThemeContext} from "../../../../Theme";

class ParagraphRenderer extends React.Component {
    static contextType = ThemeContext

    defaults = {
        'color': 'inherit',
        'font-size': '1rem'
    };

    constructor(props) {
        super(props);
        this.state = {};
    }

    render() {
        let settings;
        if (this.props.settings) {
            settings = Object.assign({}, this.defaults, this.props.settings);
        }

        let styles = {
            'color': settings['color'],
            'fontSize': settings['font-size']
        };

        return (
            <p style={styles}>{this.props.children}</p>
        )
    }
}

ParagraphRenderer.propTypes = {
    src: PropTypes.string,
    settings: PropTypes.object
};

export default ParagraphRenderer;