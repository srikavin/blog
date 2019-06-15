import React, {Component} from 'react';
import {TagStore} from '../../../../data/resource/tag';
import TagCrudList from './TagCrudList';

class TagList extends Component {
    constructor(props) {
        super(props);
        this.state = {
            tags: []
        };
    }

    componentDidMount() {
        TagStore.getAll().then(e => {
            this.setState({
                tags: e
            });
        })
    }

    render() {
        return (
            <TagCrudList updateItems={(tags) => this.setState({tags})} items={this.state.tags}/>
        );
    }
}

TagList.propTypes = {};

export default TagList;