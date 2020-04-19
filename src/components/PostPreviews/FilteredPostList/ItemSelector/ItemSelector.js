import React, {Component} from 'react';
import PropTypes from 'prop-types';
import Select from 'react-select';
import {ThemeContext} from "../../../Theme";

const lightTheme = (theme) => {
    return {
        ...theme,
        borderRadius: 4
    }
}

const darkTheme = (theme) => {
    const t = lightTheme(theme)
    return {
        ...t,
        colors: {
            ...t.colors,
            primary25: '#3e3f44',
            neutral0: '#292a2d',
            neutral10: '#393b3e',
            neutral20: '#4a4c52',
            neutral30: '#4a4c52',
            neutral50: 'white',
            neutral80: 'white'
        }
    }
}

class ItemSelector extends Component {
    static contextType = ThemeContext

    render() {
        return (
            <div className={this.props.className ? this.props.className : ''}>
                <Select isMulti={true}
                        isLoading={this.props.loading}
                        options={this.props.tags}
                        onChange={this.props.onChange}
                        getOptionLabel={(e) => e.name}
                        value={this.props.value}
                        placeholder={this.props.placeholder}
                        theme={darkTheme}
                        getOptionValue={(e) => e.id}/>
            </div>
        )
    }
}

ItemSelector.propTypes = {
    tags: PropTypes.arrayOf(PropTypes.any).isRequired,
    loading: PropTypes.bool.isRequired,
    onChange: PropTypes.func.isRequired,
    placeholder: PropTypes.string,
    className: PropTypes.string,
    value: PropTypes.arrayOf(PropTypes.any).isRequired
};

export default ItemSelector;